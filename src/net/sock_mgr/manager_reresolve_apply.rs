use super::manager::{reserved_vec, upstream_leg_flow};
use super::manager_reresolve::{
    AppliedUpstreamPlan, GroupPlanApplication, GroupTopologyReservations, ListenerReresolvePlan,
    PreparedListenerReplacement, PreparedReresolveGroup, PreparedUpstreamReplacement,
    UpstreamReresolvePlan, apply_group_plans, manager_reresolve_changed,
    precheck_group_receiver_publication, prepare_group_topology_storage, reserve_group_topology,
    resolve_group_addresses, validate_group_plan_consistency,
};
use super::manager_types::{ReresolveSummary, SocketManager};
use super::state::{
    ClientListenState, ListenerMetadata, ReresolveAction, SocketUpdateKind, UpstreamMetadata,
    UpstreamState, decide_listener_endpoint_update, decide_upstream_endpoint_update,
};
use super::transaction_lock::ManagerTransactionGuardSet;
use super::{
    ManagerError, RecoveryOutcome, SocketHandles, TransactionJournalEntry, TransactionLeg,
};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::SocketLegFlow;
use crate::net::managed_socket::{
    AssociationOperation, ReplacementBoundTopologyReservation, RetiredTopologyReservation,
    TopologyReservation,
};
use crate::net::packet_headers::select_packet_parser;
use crate::net::socket::{
    UpstreamSocketRequest, family_changed, make_socket, make_upstream_socket_for,
};
use pkthere_socket_policy::SocketRole;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

impl SocketManager {
    pub(super) fn prepare_listener_reresolve(
        &self,
        state: &ClientListenState,
        resolved: Option<SocketAddr>,
        preserve_logical_id: bool,
    ) -> io::Result<ListenerReresolvePlan> {
        let Some(resolved) = resolved else {
            return Ok(ListenerReresolvePlan::Unchanged);
        };
        let previous = state.listen_local_filter;
        let fresh = if preserve_logical_id {
            previous.with_resolved_ip(resolved)
        } else {
            LogicalEndpoint::from_socket_addr(resolved)
        };
        let (_, action) = decide_listener_endpoint_update(previous, fresh);
        if action == ReresolveAction::NoChange {
            return Ok(ListenerReresolvePlan::Unchanged);
        }

        let update = if family_changed(previous.to_socket_addr(), fresh.to_socket_addr()) {
            SocketUpdateKind::ReplacedCrossFamily
        } else {
            SocketUpdateKind::Replaced
        };
        Ok(ListenerReresolvePlan::Replace {
            destination: fresh,
            update,
        })
    }

    pub(super) fn build_listener_replacement(
        &self,
        state: &ClientListenState,
        destination: LogicalEndpoint,
        update: SocketUpdateKind,
    ) -> io::Result<PreparedListenerReplacement> {
        let replacement_evidence = state
            .evidence_key
            .replacement(destination.to_socket_addr())
            .map_err(io::Error::other)?;
        let (socket, logical_local, kernel_addr, sock_type, policy) = make_socket(
            destination.to_socket_addr(),
            self.listen_proto,
            self.listen_worker_socket_policy,
            self.timeout_action,
            self.listen_debug_unconnected,
            self.upstream_icmp_kernel_echo_self_handshake,
        )?;
        socket
            .bind_authority_identity(
                SocketRole::Listener,
                self.socket_slot,
                replacement_evidence.generation,
                true,
            )
            .map_err(io::Error::other)?;
        socket
            .configure_worker_io_lanes(self.worker_io_lanes)
            .map_err(io::Error::other)?;
        let parser = select_packet_parser(
            self.listen_proto,
            socket2::Domain::for_address(kernel_addr),
            policy,
        )?;
        let publication_gate = socket
            .reserve_topology(AssociationOperation::Replace)
            .map_err(io::Error::other)?;
        Ok(PreparedListenerReplacement {
            socket,
            metadata: Arc::new(ListenerMetadata {
                listen_local_filter: logical_local,
                listen_local_kernel_addr: kernel_addr,
                evidence_key: replacement_evidence,
                flow: None,
                listener_flow: SocketLegFlow::empty(),
                sock_type,
                policy,
                parser,
            }),
            update,
            publication_gate,
        })
    }

    pub(super) fn prepare_upstream_replacement(
        &self,
        state: &UpstreamState,
        destination: LogicalEndpoint,
    ) -> io::Result<PreparedUpstreamReplacement> {
        let replacement_evidence = state
            .evidence_key
            .replacement(destination.to_socket_addr())
            .map_err(io::Error::other)?;
        let realized = make_upstream_socket_for(UpstreamSocketRequest {
            dest: destination,
            proto: self.upstream_proto,
            req_local_id: Self::upstream_socket_local_id_request(
                self.upstream_proto,
                self.upstream_source_id_request,
                self.upstream_reply_id_request,
            ),
            timeout_act: self.timeout_action,
            debug_unconnected: self.upstream_debug_unconnected,
            force_raw_wildcard_icmp: self.force_raw_icmp_wildcard_upstream,
            allow_debug_kernel_echo_self_handshake: self.upstream_icmp_kernel_echo_self_handshake,
            worker_socket_policy: self.upstream_worker_socket_policy,
            authority_identity: Some((self.socket_slot, replacement_evidence.generation, true)),
        })?;
        let crate::net::socket::RealizedUpstreamSocket {
            socket,
            local_filter,
            remote_filter,
            local_kernel_addr: kernel_addr,
            socket_type: sock_type,
            policy,
        } = realized;
        socket
            .bind_authority_identity(
                SocketRole::Upstream,
                self.socket_slot,
                replacement_evidence.generation,
                true,
            )
            .map_err(io::Error::other)?;
        socket
            .configure_worker_io_lanes(self.worker_io_lanes)
            .map_err(io::Error::other)?;
        let parser = select_packet_parser(
            self.upstream_proto,
            socket2::Domain::for_address(kernel_addr),
            policy,
        )?;
        let update = if family_changed(
            state.upstream_remote_filter.to_socket_addr(),
            remote_filter.to_socket_addr(),
        ) {
            SocketUpdateKind::ReplacedCrossFamily
        } else {
            SocketUpdateKind::Replaced
        };
        let publication_gate = socket
            .reserve_topology(AssociationOperation::Replace)
            .map_err(io::Error::other)?;
        Ok(PreparedUpstreamReplacement {
            socket,
            metadata: Arc::new(UpstreamMetadata {
                upstream_remote_filter: remote_filter,
                upstream_local_filter: local_filter,
                upstream_local_kernel_addr: kernel_addr,
                evidence_key: replacement_evidence,
                upstream_flow: upstream_leg_flow(
                    local_filter,
                    self.upstream_source_id_request,
                    remote_filter,
                ),
                sock_type,
                policy,
                parser,
            }),
            update,
            publication_gate,
        })
    }

    pub(super) fn prepare_upstream_reresolve(
        &self,
        state: &UpstreamState,
        resolved: Option<SocketAddr>,
        preserve_logical_id: bool,
    ) -> io::Result<UpstreamReresolvePlan> {
        let Some(resolved) = resolved else {
            return Ok(UpstreamReresolvePlan::Unchanged);
        };
        let previous = state.upstream_remote_filter;
        let fresh = if preserve_logical_id {
            previous.with_resolved_ip(resolved)
        } else {
            LogicalEndpoint::from_socket_addr(resolved)
        };
        let (_, action) = decide_upstream_endpoint_update(
            previous,
            fresh,
            state.sock.is_connected(),
            state.policy,
        );
        match action {
            ReresolveAction::NoChange => Ok(UpstreamReresolvePlan::Unchanged),
            ReresolveAction::UpdateMetadataOnly => {
                let mut metadata = state.metadata.as_ref().clone();
                metadata.upstream_remote_filter = fresh;
                metadata.upstream_flow = upstream_leg_flow(
                    metadata.upstream_local_filter,
                    self.upstream_source_id_request,
                    fresh,
                );
                Ok(UpstreamReresolvePlan::Metadata(Arc::new(metadata)))
            }
            ReresolveAction::ReconnectInPlace => {
                Ok(UpstreamReresolvePlan::Reconnect { destination: fresh })
            }
            ReresolveAction::ReplaceSocket => {
                Ok(UpstreamReresolvePlan::Replace { destination: fresh })
            }
        }
    }

    pub(super) fn apply_upstream_reresolve(
        &self,
        state: &UpstreamState,
        plan: UpstreamReresolvePlan,
        reservation: &mut Option<TopologyReservation>,
        retired_reservation: &mut Option<RetiredTopologyReservation>,
        bound_reservation: &mut Option<ReplacementBoundTopologyReservation>,
    ) -> Result<AppliedUpstreamPlan, ManagerError> {
        let mut journal = TransactionJournalEntry {
            socket_slot: self.socket_slot,
            leg: TransactionLeg::Upstream,
            transition_attempted: false,
            transition_completed: false,
            recovery: RecoveryOutcome::NotRequired,
            forced_replacement: false,
            recovery_version: None,
        };
        match plan {
            UpstreamReresolvePlan::Unchanged => Ok(AppliedUpstreamPlan {
                socket: None,
                metadata: None,
                update: SocketUpdateKind::Unchanged,
                journal,
                publication_gate: None,
            }),
            UpstreamReresolvePlan::Metadata(metadata) => Ok(AppliedUpstreamPlan {
                socket: None,
                metadata: Some(metadata),
                update: SocketUpdateKind::MetadataUpdated,
                journal,
                publication_gate: None,
            }),
            UpstreamReresolvePlan::Replace { destination } => {
                journal.transition_attempted = true;
                let retired = retired_reservation.take().ok_or_else(|| {
                    ManagerError::io(
                        "record bound upstream replacement",
                        io::Error::other("retired upstream topology was not retained"),
                    )
                })?;
                let replacement = self
                    .prepare_upstream_replacement(state, destination)
                    .map_err(|error| {
                        ManagerError::io("prepare upstream replacement after quiescence", error)
                    })?;
                *bound_reservation = Some(retired.replacement_bound().map_err(|error| {
                    ManagerError::io("record bound upstream replacement", io::Error::other(error))
                })?);
                journal.transition_completed = true;
                Ok(AppliedUpstreamPlan {
                    socket: Some(replacement.socket),
                    metadata: Some(replacement.metadata),
                    update: replacement.update,
                    journal,
                    publication_gate: Some(replacement.publication_gate),
                })
            }
            UpstreamReresolvePlan::Reconnect { destination } => {
                journal.transition_attempted = true;
                let requested_local_id = Self::upstream_socket_local_id_request(
                    self.upstream_proto,
                    self.upstream_source_id_request,
                    self.upstream_reply_id_request,
                );
                let reservation = reservation.as_mut().ok_or_else(|| {
                    ManagerError::io(
                        "apply upstream reconnect",
                        io::Error::other("upstream topology was not reserved"),
                    )
                })?;
                let transition = reservation.reconnect_connected(destination.to_socket_addr());
                let kernel_addr = match transition {
                    Ok(()) => match reservation.transition_local_addr() {
                        Ok(kernel_addr)
                            if requested_local_id == 0
                                || kernel_addr.port() == requested_local_id =>
                        {
                            kernel_addr
                        }
                        Ok(kernel_addr) => {
                            let cause = format!(
                                "disconnect/reconnect changed required local id from {requested_local_id} to {}",
                                kernel_addr.port()
                            );
                            return Err(ManagerError::io(
                                "reject reconnect with changed local identity",
                                io::Error::other(cause),
                            ));
                        }
                        Err(error) => {
                            return Err(ManagerError::io(
                                "inspect reconnect local identity",
                                io::Error::other(error),
                            ));
                        }
                    },
                    Err(error) => {
                        return Err(ManagerError::io(
                            "reconnect upstream without preauthorized mismatch recovery",
                            io::Error::other(error),
                        ));
                    }
                };
                journal.transition_completed = true;
                let mut metadata = state.metadata.as_ref().clone();
                let local_filter = self.normalized_upstream_local_after_getsockname(
                    requested_local_id,
                    destination,
                    kernel_addr,
                    metadata.policy,
                );
                metadata.upstream_remote_filter = destination;
                metadata.upstream_local_filter = local_filter;
                metadata.upstream_local_kernel_addr = kernel_addr;
                metadata.upstream_flow =
                    upstream_leg_flow(local_filter, self.upstream_source_id_request, destination);
                Ok(AppliedUpstreamPlan {
                    socket: None,
                    metadata: Some(Arc::new(metadata)),
                    update: SocketUpdateKind::ReconnectedInPlace,
                    journal,
                    publication_gate: None,
                })
            }
        }
    }

    /// Re-resolve both ends and publish any changes. When `allow_listen_rebind`
    /// is true, the listening socket may be swapped if the --here DNS changes.
    /// Returns handles and a flag indicating whether the listener changed.
    pub fn reresolve(
        &self,
        allow_upstream: bool,
        allow_listen_rebind: bool,
    ) -> Result<SocketHandles, ManagerError> {
        self.reresolve_with_addresses(allow_upstream, allow_listen_rebind, None, None)
            .map(|summary| summary.handles)
    }

    pub(crate) fn reresolve_with_addresses(
        &self,
        allow_upstream: bool,
        allow_listen_rebind: bool,
        listen_addr: Option<SocketAddr>,
        upstream_addr: Option<SocketAddr>,
    ) -> Result<ReresolveSummary, ManagerError> {
        let transition = Self::begin_reresolve_group_with_addresses(
            &[self],
            allow_upstream,
            allow_listen_rebind,
            listen_addr,
            upstream_addr,
        )?;
        let mut summaries = transition.publish()?;
        summaries
            .pop()
            .ok_or_else(|| ManagerError::TransactionFailed {
                operation: "single-manager re-resolution",
                cause: "group transaction returned no manager summary".to_string(),
                journal: Vec::new(),
            })
    }

    pub(crate) fn begin_reresolve_group_with_addresses<'manager>(
        managers: &[&'manager Self],
        allow_upstream: bool,
        allow_listen_rebind: bool,
        listen_addr: Option<SocketAddr>,
        upstream_addr: Option<SocketAddr>,
    ) -> Result<PreparedReresolveGroup<'manager>, ManagerError> {
        let preserve_listener_id = listen_addr.is_none();
        let preserve_upstream_id = upstream_addr.is_none();
        let mut ordered = managers.to_vec();
        ordered.sort_unstable_by_key(|manager| manager.socket_slot);
        if ordered
            .windows(2)
            .any(|pair| pair[0].socket_slot == pair[1].socket_slot)
        {
            return Err(ManagerError::io(
                "prepare grouped re-resolution",
                io::Error::other("duplicate socket slot in re-resolution transaction"),
            ));
        }

        // Name resolution is external work and must finish before any manager
        // transaction lock is acquired.
        let resolved = resolve_group_addresses(
            &ordered,
            allow_upstream,
            allow_listen_rebind,
            listen_addr,
            upstream_addr,
        )?;
        let mut listener_snapshots =
            reserved_vec(ordered.len(), "prepare grouped listener state snapshots")?;
        let mut upstream_snapshots =
            reserved_vec(ordered.len(), "prepare grouped upstream state snapshots")?;
        let initial_listener_guard_storage =
            reserved_vec(ordered.len(), "prepare grouped listener guard storage")?;
        let initial_upstream_guard_storage =
            reserved_vec(ordered.len(), "prepare grouped upstream guard storage")?;
        let listener_guard_storage =
            reserved_vec(ordered.len(), "prepare grouped publication listener guards")?;
        let upstream_guard_storage =
            reserved_vec(ordered.len(), "prepare grouped publication upstream guards")?;
        let mut changed = reserved_vec(ordered.len(), "prepare grouped change set")?;
        let mut capacities = reserved_vec(ordered.len(), "prepare grouped version capacities")?;
        let mut listener_plans = reserved_vec(ordered.len(), "prepare grouped listener plans")?;
        let mut upstream_plans = reserved_vec(ordered.len(), "prepare grouped upstream plans")?;
        let mut old_state = reserved_vec(ordered.len(), "prepare grouped old state")?;
        let topology_storage = prepare_group_topology_storage(ordered.len())?;
        let applied_listener_storage = reserved_vec(ordered.len(), "apply grouped listener plans")?;
        let applied_upstream_storage = reserved_vec(ordered.len(), "apply grouped upstream plans")?;
        let mut listener_updates = reserved_vec(ordered.len(), "prepare grouped listener updates")?;
        let mut listener_publication_gates =
            reserved_vec(ordered.len(), "prepare grouped listener publication gates")?;
        let mut upstream_publication_gates =
            reserved_vec(ordered.len(), "prepare grouped upstream publication gates")?;
        let mut listener_receivers =
            reserved_vec(ordered.len(), "stage grouped listener receivers")?;
        let mut upstream_receivers =
            reserved_vec(ordered.len(), "stage grouped upstream receivers")?;
        let mut summaries = reserved_vec(ordered.len(), "prepare grouped re-resolution summaries")?;
        let mut bound_listener_topology = reserved_vec(
            ordered.len(),
            "prepare replacement-bound listener topology storage",
        )?;
        let mut bound_upstream_topology = reserved_vec(
            ordered.len(),
            "prepare replacement-bound upstream topology storage",
        )?;
        bound_listener_topology.resize_with(ordered.len(), || None);
        bound_upstream_topology.resize_with(ordered.len(), || None);

        let transaction_deadline = std::time::Instant::now()
            + crate::net::sock_mgr::transaction_lock::MANAGER_RESERVATION_TIMEOUT;
        let transactions = ManagerTransactionGuardSet::try_collect(
            ordered
                .iter()
                .map(|manager| manager.lock_transaction_until(transaction_deadline)),
        )?;
        let listeners = crate::authority::AuthorityMutexGuardSet::collect_ordered_into(
            initial_listener_guard_storage,
            ordered.iter().map(|manager| {
                super::manager::lock_manager_authority(&manager.client_listen, "listener manager")
            }),
        )?;
        let upstreams = crate::authority::AuthorityMutexGuardSet::collect_ordered_into(
            initial_upstream_guard_storage,
            ordered.iter().map(|manager| {
                super::manager::lock_manager_authority(&manager.upstream_state, "upstream manager")
            }),
        )?;
        for listener in &listeners {
            listener_snapshots.push((**listener).clone());
        }
        for upstream in &upstreams {
            upstream_snapshots.push((**upstream).clone());
        }
        drop(upstreams);
        drop(listeners);

        for (((_, listener), upstream), resolved) in ordered
            .iter()
            .zip(&listener_snapshots)
            .zip(&upstream_snapshots)
            .zip(&resolved)
        {
            changed.push(manager_reresolve_changed(
                listener,
                upstream,
                *resolved,
                preserve_listener_id,
                preserve_upstream_id,
            ));
        }
        for ((manager, transaction), changed) in ordered.iter().zip(&transactions).zip(&changed) {
            capacities.push(
                changed
                    .then(|| manager.precheck_version_capacity(transaction))
                    .transpose()?,
            );
        }

        // Planning reads manager-owned state only. Descriptor binding and
        // association syscalls happen after these state guards are released;
        // the manager transaction guards continue to block readers and other
        // writers until the complete group is committed.
        for ((manager, listener), resolved) in
            ordered.iter().zip(&listener_snapshots).zip(&resolved)
        {
            listener_plans.push(
                manager
                    .prepare_listener_reresolve(listener, resolved.listener, preserve_listener_id)
                    .map_err(|error| ManagerError::io("prepare listener re-resolution", error))?,
            );
        }
        for ((manager, upstream), resolved) in
            ordered.iter().zip(&upstream_snapshots).zip(&resolved)
        {
            upstream_plans.push(
                manager
                    .prepare_upstream_reresolve(upstream, resolved.upstream, preserve_upstream_id)
                    .map_err(|error| ManagerError::io("prepare upstream re-resolution", error))?,
            );
        }
        precheck_group_receiver_publication(&ordered)?;
        for (listener, upstream) in listener_snapshots.iter().zip(&upstream_snapshots) {
            old_state.push((listener.flow, listener.evidence_key, upstream.evidence_key));
        }

        let GroupTopologyReservations {
            listener: listener_topology,
            upstream: mut upstream_topology,
            retired_listener: mut retired_listener_topology,
            retired_upstream: mut retired_upstream_topology,
        } = reserve_group_topology(
            &ordered,
            &listener_snapshots,
            &upstream_snapshots,
            &listener_plans,
            &upstream_plans,
            topology_storage,
        )?;
        let (applied_listeners, mut applied_upstreams) = apply_group_plans(
            GroupPlanApplication {
                ordered: &ordered,
                listener_snapshots: &listener_snapshots,
                upstream_snapshots: &upstream_snapshots,
                listener_plans,
                upstream_plans,
                upstream_topology: &mut upstream_topology,
                retired_listener_topology: &mut retired_listener_topology,
                retired_upstream_topology: &mut retired_upstream_topology,
                bound_listener_topology: &mut bound_listener_topology,
                bound_upstream_topology: &mut bound_upstream_topology,
            },
            applied_listener_storage,
            applied_upstream_storage,
        )?;
        for applied in &applied_listeners {
            listener_updates.push(
                applied
                    .replacement
                    .as_ref()
                    .map_or(SocketUpdateKind::Unchanged, |replacement| {
                        replacement.update
                    }),
            );
        }
        applied_upstreams =
            validate_group_plan_consistency(&listener_updates, applied_upstreams, &changed)?;

        let mut listener_states = listener_snapshots;
        let mut upstream_states = upstream_snapshots;

        for (listener, applied) in listener_states.iter_mut().zip(applied_listeners) {
            match applied.replacement {
                None => {
                    listener_publication_gates.push(None);
                    listener_receivers.push(None);
                }
                Some(replacement) => {
                    listener_receivers.push(Some((
                        replacement.socket.clone(),
                        crate::net::managed_socket::ManagedReceiver::new(&replacement.socket),
                    )));
                    listener.sock = replacement.socket;
                    listener.metadata = replacement.metadata;
                    listener_publication_gates.push(Some(replacement.publication_gate));
                }
            }
        }

        for (upstream, applied) in upstream_states.iter_mut().zip(&mut applied_upstreams) {
            if let Some(socket) = applied.socket.take() {
                upstream_receivers.push(Some((
                    socket.clone(),
                    crate::net::managed_socket::ManagedReceiver::new(&socket),
                )));
                upstream.sock = socket;
            } else {
                upstream_receivers.push(None);
            }
            upstream_publication_gates.push(applied.publication_gate.take());
            if let Some(metadata) = applied.metadata.take() {
                upstream.metadata = metadata;
            }
        }

        for index in 0..ordered.len() {
            let manager = ordered[index];
            let version = manager.version.current();
            let handles = SocketHandles {
                listener: Arc::clone(&listener_states[index].metadata),
                client_sock: listener_states[index].sock.clone(),
                upstream: Arc::clone(&upstream_states[index].metadata),
                upstream_sock: upstream_states[index].sock.clone(),
                version,
            };
            summaries.push(ReresolveSummary {
                socket_slot: manager.socket_slot,
                old_listener_key: old_state[index].1,
                new_listener_key: handles.listener.evidence_key,
                old_upstream_key: old_state[index].2,
                new_upstream_key: handles.upstream.evidence_key,
                handles,
                listener_update: listener_updates[index],
                upstream_update: applied_upstreams[index].update,
            });
        }
        Ok(PreparedReresolveGroup {
            ordered,
            summaries,
            listener_states,
            upstream_states,
            capacities,
            listener_receivers,
            upstream_receivers,
            listener_topology,
            upstream_topology,
            retired_listener_topology: bound_listener_topology,
            retired_upstream_topology: bound_upstream_topology,
            listener_publication: listener_publication_gates,
            upstream_publication: upstream_publication_gates,
            transactions,
            listener_guard_storage,
            upstream_guard_storage,
        })
    }
}
