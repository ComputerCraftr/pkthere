use super::group_publication::{
    CommittedGroupPublication, PublicationStep, fail_group_publication, prepare_clear_publication,
    production_group_publication,
};
use super::manager::{
    apply_listener_clear_strategies, lock_manager_authorities, lock_manager_authority,
    recover_failed_client_flow_establishment, reserved_vec, transaction_failure,
};
use super::manager_types::{
    ClientFlowSocketTransitionPhase, ClientFlowUpdate, PreparedClientFlowGroup,
    PreparedClientFlowTransition, SocketManager,
};
use super::receiver_slot::ReceiverRole;
use super::transaction_lock::ManagerTransactionGuardSet;
use super::{
    ClearedClientFlow, ManagerError, PublishedUpdate, RecoveryOutcome, SocketHandles,
    TransactionJournalEntry, TransactionLeg,
};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::SocketLegFlow;
use crate::flow_state::ClientFlowReservation;
use crate::net::icmp_support::choose_upstream_icmp_ids;
use crate::net::managed_socket::{
    AssociationOperation, RetiredTopologyReservation, TopologyReservation,
};
use pkthere_socket_policy::{ListenerLockLifecycle, ResolvedSocketPolicy};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

fn group_publication_failure(operation: &'static str, error: impl std::fmt::Debug) -> ManagerError {
    fail_group_publication(operation, error)
}

struct ClearGroupPublication<'borrow, 'manager, 'reservation, 'flow> {
    ordered: &'borrow [&'manager SocketManager],
    transitioned_states: &'borrow [super::state::ClientListenState],
    metadata_changed: &'borrow [bool],
    listener_guards: Option<
        crate::authority::AuthorityMutexGuardSet<
            'manager,
            crate::authority::tags::ManagerState,
            super::state::ClientListenState,
        >,
    >,
    upstream_guards: Option<
        crate::authority::AuthorityMutexGuardSet<
            'manager,
            crate::authority::tags::ManagerState,
            super::state::UpstreamState,
        >,
    >,
    capacities: &'borrow mut [Option<super::version::VersionCapacityGuard>],
    transaction_guards: Option<ManagerTransactionGuardSet<'manager>>,
    topology: &'borrow mut [Option<TopologyReservation>],
    retired_topology: &'borrow mut [Option<RetiredTopologyReservation>],
    replacement_publication: &'borrow mut [Option<TopologyReservation>],
    staged_receivers: &'borrow mut [Option<crate::net::managed_socket::ManagedReceiver>],
    journal: &'borrow mut [TransactionJournalEntry],
    updates: &'borrow mut Vec<PublishedUpdate>,
    visibility: Option<crate::flow_state::CommittedClientFlowTopology<'reservation, 'flow>>,
    next_changed_manager: usize,
}

impl CommittedGroupPublication for ClearGroupPublication<'_, '_, '_, '_> {
    type Error = ManagerError;
    type Output = ();

    fn publish_receiver(&mut self, _step: PublicationStep<'_, 0>) -> Result<(), Self::Error> {
        let listener_guards = self
            .listener_guards
            .as_mut()
            .ok_or(ManagerError::Poisoned {
                authority: "clear listener publication guards",
            })?;
        for index in 0..self.ordered.len() {
            if self.retired_topology[index].is_some() {
                let receiver =
                    self.staged_receivers[index]
                        .take()
                        .ok_or(ManagerError::Poisoned {
                            authority: "staged listener receiver publication",
                        })?;
                self.ordered[index].publish_staged_receiver(
                    ReceiverRole::Listener,
                    &self.transitioned_states[index].sock,
                    receiver,
                )?;
                *listener_guards[index] = self.transitioned_states[index].clone();
            }
        }
        Ok(())
    }

    fn publish_manager_metadata(
        &mut self,
        _step: PublicationStep<'_, 1>,
    ) -> Result<(), Self::Error> {
        let listener_guards = self
            .listener_guards
            .as_mut()
            .ok_or(ManagerError::Poisoned {
                authority: "clear listener publication guards",
            })?;
        for state in listener_guards {
            state.flow = None;
            state.listener_flow = SocketLegFlow::empty();
        }
        Ok(())
    }

    fn publish_manager(
        &mut self,
        _step: PublicationStep<'_, 2>,
        _publication_index: usize,
    ) -> Result<(), Self::Error> {
        let index = (self.next_changed_manager..self.ordered.len())
            .find(|index| self.metadata_changed[*index] || self.retired_topology[*index].is_some())
            .ok_or(ManagerError::Poisoned {
                authority: "changed manager publication index",
            })?;
        self.next_changed_manager = index + 1;
        let replacement_committed = self.retired_topology[index].is_some();
        let capacity = self.capacities[index]
            .take()
            .ok_or(ManagerError::Poisoned {
                authority: "changed manager version capacity",
            })?;
        let transaction_guards =
            self.transaction_guards
                .as_ref()
                .ok_or(ManagerError::Poisoned {
                    authority: "clear manager reservations",
                })?;
        let version =
            self.ordered[index].publish_prechecked(&transaction_guards[index], capacity)?;
        if replacement_committed {
            self.journal[index].recovery_version = Some(version);
        }
        let listener_guards = self
            .listener_guards
            .as_ref()
            .ok_or(ManagerError::Poisoned {
                authority: "clear listener publication guards",
            })?;
        let upstream_guards = self
            .upstream_guards
            .as_ref()
            .ok_or(ManagerError::Poisoned {
                authority: "clear upstream publication guards",
            })?;
        self.updates.push(PublishedUpdate::new(SocketHandles {
            listener: Arc::clone(&listener_guards[index].metadata),
            client_sock: listener_guards[index].sock.clone(),
            upstream: Arc::clone(&upstream_guards[index].metadata),
            upstream_sock: upstream_guards[index].sock.clone(),
            version,
        }));
        Ok(())
    }

    fn publish_socket_topology(
        &mut self,
        _step: PublicationStep<'_, 3>,
    ) -> Result<(), Self::Error> {
        drop(self.upstream_guards.take());
        drop(self.listener_guards.take());
        for index in (0..self.replacement_publication.len()).rev() {
            if let Some(publication_gate) = self.replacement_publication[index].take() {
                publication_gate.commit_publication().map_err(|error| {
                    ManagerError::io("publish replacement activation", io::Error::other(error))
                })?;
            }
        }
        for index in (0..self.topology.len()).rev() {
            let reservation = self.topology[index].take();
            if self.retired_topology[index].is_some() {
                let retired =
                    self.retired_topology[index]
                        .take()
                        .ok_or(ManagerError::Poisoned {
                            authority: "retired listener topology publication",
                        })?;
                retired.commit().map_err(|error| {
                    ManagerError::io("publish retired listener topology", io::Error::other(error))
                })?;
            } else {
                reservation
                    .ok_or(ManagerError::Poisoned {
                        authority: "listener topology reservation publication",
                    })?
                    .commit()
                    .map_err(|error| {
                        ManagerError::io(
                            "publish listener topology reservation",
                            io::Error::other(error),
                        )
                    })?;
            }
        }
        Ok(())
    }

    fn commit_manager_reservations(
        &mut self,
        _step: PublicationStep<'_, 4>,
    ) -> Result<(), Self::Error> {
        self.transaction_guards
            .take()
            .ok_or(ManagerError::Poisoned {
                authority: "clear manager reservations",
            })?
            .commit_all()
            .map_err(|cause| ManagerError::Reservation {
                operation: "commit grouped manager clear",
                cause,
            })
    }

    fn publish_flow_visibility(
        &mut self,
        _step: PublicationStep<'_, 5>,
    ) -> Result<(), Self::Error> {
        self.visibility
            .take()
            .ok_or(ManagerError::Poisoned {
                authority: "clear flow visibility reservation",
            })?
            .publish()
            .map_err(|error| {
                ManagerError::io("publish clear flow visibility", io::Error::other(error))
            })
    }

    fn finish(self, _step: PublicationStep<'_, 6>) {}
}

impl SocketManager {
    pub(crate) fn prepare_client_flow_group<'a>(
        managers: &[&'a Self],
        update: ClientFlowUpdate,
    ) -> Result<PreparedClientFlowGroup<'a>, ManagerError> {
        let count = managers.len();
        let mut ordered = reserved_vec(count, "prepare shared client-flow managers")?;
        ordered.extend_from_slice(managers);
        ordered.sort_unstable_by_key(|manager| manager.socket_slot);
        if ordered.is_empty() {
            return Err(ManagerError::io(
                "prepare shared client flow",
                io::Error::other("shared-flow transaction requires at least one socket manager"),
            ));
        }
        if ordered
            .windows(2)
            .any(|pair| pair[0].socket_slot == pair[1].socket_slot)
        {
            return Err(ManagerError::io(
                "prepare shared client flow",
                io::Error::other("duplicate socket slot in shared-flow transaction"),
            ));
        }
        if !ordered
            .iter()
            .any(|manager| manager.socket_slot == update.admitting_listener_slot)
        {
            return Err(ManagerError::io(
                "prepare shared client flow",
                io::Error::other("admitting listener slot is not a transaction participant"),
            ));
        }

        let mut versions = reserved_vec(count, "prepare shared client-flow versions")?;
        versions.extend(ordered.iter().map(|manager| manager.version.current()));
        let listener_guard_storage = reserved_vec(count, "prepare shared listener guard storage")?;
        let mut listener_states = reserved_vec(count, "prepare shared listener states")?;
        let listener_guards = crate::authority::AuthorityMutexGuardSet::collect_ordered_into(
            listener_guard_storage,
            ordered
                .iter()
                .map(|manager| lock_manager_authority(&manager.client_listen, "listener manager")),
        )?;
        listener_states.extend(listener_guards.iter().map(|state| (**state).clone()));
        drop(listener_guards);

        let upstream_guard_storage = reserved_vec(count, "prepare shared upstream guard storage")?;
        let mut upstream_states = reserved_vec(count, "prepare shared upstream states")?;
        let upstream_guards = crate::authority::AuthorityMutexGuardSet::collect_ordered_into(
            upstream_guard_storage,
            ordered
                .iter()
                .map(|manager| lock_manager_authority(&manager.upstream_state, "upstream manager")),
        )?;
        upstream_states.extend(upstream_guards.iter().map(|state| (**state).clone()));
        drop(upstream_guards);

        if ordered
            .iter()
            .zip(&versions)
            .any(|(manager, version)| manager.version.current() != *version)
        {
            return Err(ManagerError::io(
                "prepare shared client flow",
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "socket manager changed while client-flow state was prepared",
                ),
            ));
        }

        let mut listener_associations =
            reserved_vec(count, "prepare shared listener associations")?;
        listener_associations.extend(listener_states.iter().map(|state| state.sock.association()));
        let mut published_listener_metadata =
            reserved_vec(count, "prepare shared listener metadata")?;
        for state in &listener_states {
            let mut metadata = (*state.metadata).clone();
            metadata.flow = Some(update.flow);
            metadata.listener_flow = update.listener_flow;
            published_listener_metadata.push(Arc::new(metadata));
        }

        let transaction_guard_storage =
            reserved_vec(count, "prepare shared transaction guard storage")?;
        let listener_guard_storage = reserved_vec(count, "prepare final listener guard storage")?;
        let upstream_guard_storage = reserved_vec(count, "prepare final upstream guard storage")?;
        let capacities = reserved_vec(count, "prepare shared version capacities")?;
        let topology = reserved_vec(count, "prepare shared topology reservations")?;
        let published = reserved_vec(count, "prepare shared publication output")?;
        let mut transition_phases = reserved_vec(count, "prepare shared transition phases")?;
        transition_phases.resize(count, ClientFlowSocketTransitionPhase::Reserved);
        let mut journal = reserved_vec(count, "prepare shared transaction journal")?;
        journal.extend(ordered.iter().map(|manager| TransactionJournalEntry {
            socket_slot: manager.socket_slot,
            leg: TransactionLeg::Listener,
            transition_attempted: false,
            transition_completed: false,
            recovery: RecoveryOutcome::NotRequired,
            forced_replacement: false,
            recovery_version: None,
        }));

        Ok(PreparedClientFlowGroup {
            ordered,
            update,
            versions,
            listener_states,
            upstream_states,
            listener_associations,
            published_listener_metadata,
            transaction_guard_storage,
            listener_guard_storage,
            upstream_guard_storage,
            capacities,
            transition_phases,
            journal,
            topology,
            published,
        })
    }

    pub(crate) fn reconcile_stale_send_association(
        &self,
        handles: &SocketHandles,
        upstream: bool,
        expected_epoch: u64,
    ) -> Result<bool, ManagerError> {
        if handles.version != self.version.current() {
            return Err(ManagerError::io(
                "reconcile stale send association",
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "socket-manager version changed before association recovery",
                ),
            ));
        }
        let current = self.capture_handles_without_flow_read()?;
        let (provided, authoritative) = if upstream {
            (&handles.upstream_sock, &current.upstream_sock)
        } else {
            (&handles.client_sock, &current.client_sock)
        };
        if !provided.same_descriptor(authoritative) {
            return Err(ManagerError::io(
                "reconcile stale send association",
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "socket descriptor changed before association recovery",
                ),
            ));
        }
        authoritative
            .reconcile_destination_required(expected_epoch)
            .map_err(|error| ManagerError::io("reconcile stale send association", error))
    }

    pub(crate) fn set_upstream_peer_ids_group_at_topology(
        managers: &[&Self],
        observed_socket_slot: u32,
        observed_topology_epoch: u64,
        source_id: u16,
        reply_id: u16,
    ) -> Result<Vec<PublishedUpdate>, ManagerError> {
        let mut ordered = managers.to_vec();
        ordered.sort_unstable_by_key(|manager| manager.socket_slot);
        if ordered.is_empty() {
            return Err(ManagerError::io(
                "clear shared client flow",
                io::Error::other("shared-flow transaction requires at least one socket manager"),
            ));
        }
        if ordered
            .windows(2)
            .any(|pair| pair[0].socket_slot == pair[1].socket_slot)
        {
            return Err(ManagerError::io(
                "set shared upstream peer IDs",
                io::Error::other("duplicate socket slot in shared peer-ID transaction"),
            ));
        }
        if !ordered
            .iter()
            .any(|manager| manager.socket_slot == observed_socket_slot)
        {
            return Err(ManagerError::io(
                "set shared upstream peer IDs",
                io::Error::other(format!(
                    "observed upstream socket slot {observed_socket_slot} is not a transaction participant"
                )),
            ));
        }

        let transaction_deadline =
            Instant::now() + crate::net::sock_mgr::transaction_lock::MANAGER_RESERVATION_TIMEOUT;
        let transactions = ManagerTransactionGuardSet::try_collect(
            ordered
                .iter()
                .map(|manager| manager.lock_transaction_until(transaction_deadline)),
        )?;
        let upstream_sockets = ordered
            .iter()
            .map(|manager| {
                lock_manager_authority(&manager.upstream_state, "upstream manager")
                    .map(|state| state.sock.clone())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut topology = Vec::with_capacity(ordered.len());
        for (manager, socket) in ordered.iter().zip(&upstream_sockets) {
            let reservation = match socket.reserve_topology(AssociationOperation::PublishMetadata) {
                Ok(reservation) => reservation,
                Err(error) => {
                    while topology.pop().is_some() {}
                    return Err(ManagerError::io(
                        "reserve upstream peer-ID publication topology",
                        io::Error::other(error),
                    ));
                }
            };
            if manager.socket_slot == observed_socket_slot
                && reservation.previous_epoch() != observed_topology_epoch
            {
                drop(reservation);
                while topology.pop().is_some() {}
                return Err(ManagerError::io(
                    "set upstream peer IDs at observed topology",
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "upstream topology changed before commit",
                    ),
                ));
            }
            topology.push(reservation);
        }
        let listeners = lock_manager_authorities(
            ordered.iter().map(|manager| &manager.client_listen),
            "listener manager",
        )?;
        let mut upstreams = lock_manager_authorities(
            ordered.iter().map(|manager| &manager.upstream_state),
            "upstream manager",
        )?;
        let changed = upstreams
            .iter()
            .map(|upstream| {
                upstream.upstream_remote_filter.id() != reply_id
                    || upstream
                        .upstream_flow
                        .inbound
                        .is_some_and(|inbound| inbound.src.id() != source_id)
                    || upstream
                        .upstream_flow
                        .outbound
                        .is_some_and(|outbound| outbound.dst.id() != reply_id)
            })
            .collect::<Vec<_>>();
        let mut capacities = ordered
            .iter()
            .zip(&transactions)
            .zip(&changed)
            .map(|((manager, transaction), changed)| {
                changed
                    .then(|| manager.precheck_version_capacity(transaction))
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (upstream, changed) in upstreams.iter_mut().zip(&changed) {
            if !changed {
                continue;
            }
            upstream.upstream_remote_filter = upstream.upstream_remote_filter.with_id(reply_id);
            if let Some(mut inbound) = upstream.upstream_flow.inbound {
                inbound.src = inbound.src.with_id(source_id);
                upstream.upstream_flow.inbound = Some(inbound);
            }
            if let Some(mut outbound) = upstream.upstream_flow.outbound {
                outbound.dst = outbound.dst.with_id(reply_id);
                upstream.upstream_flow.outbound = Some(outbound);
            }
        }

        let mut updates = Vec::with_capacity(ordered.len());
        for index in 0..ordered.len() {
            let version = if changed[index] {
                let capacity = capacities
                    .get_mut(index)
                    .and_then(Option::take)
                    .ok_or_else(|| {
                        transaction_failure(
                            "publish upstream peer IDs",
                            "changed manager lost its version capacity",
                            Vec::new(),
                        )
                    })?;
                ordered[index].publish_prechecked(&transactions[index], capacity)?
            } else {
                ordered[index].version.current()
            };
            updates.push(PublishedUpdate::new(SocketHandles {
                listener: Arc::clone(&listeners[index].metadata),
                client_sock: listeners[index].sock.clone(),
                upstream: Arc::clone(&upstreams[index].metadata),
                upstream_sock: upstreams[index].sock.clone(),
                version,
            }));
        }
        drop(upstreams);
        drop(listeners);
        for reservation in topology.into_iter().rev() {
            reservation
                .commit()
                .map_err(|error| ManagerError::TransactionFailed {
                    operation: "publish upstream peer IDs",
                    cause: format!("could not reopen committed upstream topology: {error}"),
                    journal: Vec::new(),
                })?;
        }
        transactions
            .commit_all()
            .map_err(|cause| ManagerError::Reservation {
                operation: "complete upstream peer-ID transaction",
                cause,
            })?;
        Ok(updates)
    }

    pub(crate) fn clear_client_flow_group(
        managers: &[&Self],
        flow_transaction: &mut ClientFlowReservation<'_>,
    ) -> Result<ClearedClientFlow, ManagerError> {
        let mut ordered = managers.to_vec();
        ordered.sort_unstable_by_key(|manager| manager.socket_slot);
        if ordered.is_empty() {
            return Err(ManagerError::io(
                "establish shared client flow",
                io::Error::other("shared-flow transaction requires at least one socket manager"),
            ));
        }
        if ordered
            .windows(2)
            .any(|pair| pair[0].socket_slot == pair[1].socket_slot)
        {
            return Err(ManagerError::io(
                "clear shared client flow",
                io::Error::other("duplicate socket slot in shared-flow transaction"),
            ));
        }
        let transaction_deadline =
            Instant::now() + crate::net::sock_mgr::transaction_lock::MANAGER_RESERVATION_TIMEOUT;
        let visibility = flow_transaction
            .reserve_topology_until(transaction_deadline)
            .map_err(|error| ManagerError::TransactionFailed {
                operation: "clear shared client flow",
                cause: format!("could not reserve flow-topology visibility: {error}"),
                journal: Vec::new(),
            })?;
        let transaction_guards = ManagerTransactionGuardSet::try_collect(
            ordered
                .iter()
                .map(|manager| manager.lock_transaction_until(transaction_deadline)),
        )?;
        let listener_guards = lock_manager_authorities(
            ordered.iter().map(|manager| &manager.client_listen),
            "listener manager",
        )?;
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
        for manager in &ordered {
            manager.precheck_receiver_publication(ReceiverRole::Listener)?;
        }
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
        let mut transitioned_states = listener_guards
            .iter()
            .map(|state| (**state).clone())
            .collect::<Vec<_>>();
        let was_connected = transitioned_states
            .iter()
            .map(|state| state.sock.is_connected())
            .collect::<Vec<_>>();
        drop(listener_guards);
        let mut topology = Vec::with_capacity(transitioned_states.len());
        for (state, connected) in transitioned_states.iter().zip(&was_connected) {
            let operation = if *connected {
                AssociationOperation::Disconnect
            } else {
                AssociationOperation::PublishMetadata
            };
            match state.sock.reserve_topology(operation) {
                Ok(reservation) => topology.push(Some(reservation)),
                Err(error) => {
                    while topology.pop().is_some() {}
                    return Err(ManagerError::io(
                        "reserve shared listener clear topology",
                        io::Error::other(error),
                    ));
                }
            }
        }

        let mut replacement_publication = std::iter::repeat_with(|| None)
            .take(ordered.len())
            .collect::<Vec<Option<TopologyReservation>>>();
        let mut retired_topology = std::iter::repeat_with(|| None)
            .take(ordered.len())
            .collect::<Vec<Option<RetiredTopologyReservation>>>();
        apply_listener_clear_strategies(
            &ordered,
            &mut transitioned_states,
            &was_connected,
            &mut topology,
            &mut retired_topology,
            &mut journal,
            &mut replacement_publication,
        )?;
        let receiver_changed = retired_topology.iter().any(Option::is_some);
        let mut staged_receivers = transitioned_states
            .iter()
            .zip(&retired_topology)
            .map(|(state, retired)| {
                retired
                    .is_some()
                    .then(|| crate::net::managed_socket::ManagedReceiver::new(&state.sock))
            })
            .collect::<Vec<_>>();
        let (mut updates, changed_manager_count, required_components) =
            prepare_clear_publication(&may_need_publication, receiver_changed)?;

        let manager_prepared = match visibility
            .socket_transitions_applied()
            .and_then(crate::flow_state::ClientFlowSocketTransitionsApplied::manager_state_prepared)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(ManagerError::TransactionFailed {
                    operation: "clear shared client flow",
                    cause: format!("could not stage flow-topology transaction: {error}"),
                    journal,
                });
            }
        };
        let (visibility, dropped_handshake) =
            manager_prepared.commit_session_with(ClientFlowReservation::reset)?;
        let publication = production_group_publication(changed_manager_count, required_components)
            .map_err(|error| group_publication_failure("initialization", error))?;

        let listener_guards = lock_manager_authorities(
            ordered.iter().map(|manager| &manager.client_listen),
            "listener manager",
        )
        .map_err(|error| group_publication_failure("listener lock reacquisition", error))?;
        let upstream_guards = lock_manager_authorities(
            ordered.iter().map(|manager| &manager.upstream_state),
            "upstream manager",
        )
        .map_err(|error| group_publication_failure("upstream lock reacquisition", error))?;
        publication
            .publish_committed(ClearGroupPublication {
                ordered: &ordered,
                transitioned_states: &transitioned_states,
                metadata_changed: &metadata_changed,
                listener_guards: Some(listener_guards),
                upstream_guards: Some(upstream_guards),
                capacities: &mut capacities,
                transaction_guards: Some(transaction_guards),
                topology: &mut topology,
                retired_topology: &mut retired_topology,
                replacement_publication: &mut replacement_publication,
                staged_receivers: &mut staged_receivers,
                journal: &mut journal,
                updates: &mut updates,
                visibility: Some(visibility),
                next_changed_manager: 0,
            })
            .map_err(|error| group_publication_failure("committed publication", error))?;
        Ok(ClearedClientFlow {
            updates,
            dropped_handshake,
        })
    }

    pub(crate) fn begin_client_flow_group_transition<'manager, 'reservation, 'flow>(
        mut prepared: PreparedClientFlowGroup<'manager>,
        flow_transaction: &'reservation mut ClientFlowReservation<'flow>,
    ) -> Result<PreparedClientFlowTransition<'manager, 'reservation, 'flow>, ManagerError> {
        if flow_transaction.is_locked()? {
            return Err(ManagerError::io(
                "establish shared client flow",
                io::Error::other("client flow is already locked"),
            ));
        }

        let ordered = &prepared.ordered;
        let update = prepared.update;
        let unexpected_association_cause = "listener is not unconnected before shared-flow lock";
        let transaction_deadline =
            Instant::now() + crate::net::sock_mgr::transaction_lock::MANAGER_RESERVATION_TIMEOUT;
        let visibility = flow_transaction
            .reserve_topology_until(transaction_deadline)
            .map_err(|error| ManagerError::TransactionFailed {
                operation: "establish shared client flow",
                cause: format!("could not reserve flow-topology visibility: {error}"),
                journal: Vec::new(),
            })?;

        let transaction_guards = ManagerTransactionGuardSet::try_collect_into(
            std::mem::take(&mut prepared.transaction_guard_storage),
            ordered
                .iter()
                .map(|manager| manager.lock_transaction_until(transaction_deadline)),
        )?;
        if ordered
            .iter()
            .zip(&prepared.versions)
            .any(|(manager, version)| manager.version.current() != *version)
        {
            return Err(ManagerError::io(
                "establish shared client flow",
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "socket manager changed before client-flow transaction reservation",
                ),
            ));
        }
        let listener_lifecycle = prepared.listener_states[0].policy.listener_lifecycle;
        if prepared
            .listener_states
            .iter()
            .any(|state| state.policy.listener_lifecycle != listener_lifecycle)
        {
            return Err(ManagerError::io(
                "establish shared client flow",
                io::Error::other(
                    "shared-flow transaction participants resolved different listener lifecycles",
                ),
            ));
        }
        if prepared
            .listener_states
            .iter()
            .zip(&prepared.listener_associations)
            .any(|(state, association)| state.sock.association() != *association)
        {
            return Err(ManagerError::io(
                "establish shared client flow",
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "listener association changed before client-flow transaction reservation",
                ),
            ));
        }
        // Policy selects the fast path; this transaction selects its stable owner.
        let connected_owner_slot = listener_lifecycle
            .is_some_and(ListenerLockLifecycle::connects_after_lock)
            .then_some(ordered[0].socket_slot);
        for (manager, transaction) in ordered.iter().zip(&transaction_guards) {
            prepared
                .capacities
                .push(Some(manager.precheck_version_capacity(transaction)?));
        }
        for manager in ordered {
            manager.precheck_receiver_publication(ReceiverRole::Listener)?;
        }
        for state in &prepared.listener_states {
            match state.sock.reserve_topology(AssociationOperation::Connect) {
                Ok(reservation) => prepared.topology.push(Some(reservation)),
                Err(error) => {
                    while prepared.topology.pop().is_some() {}
                    return Err(ManagerError::io(
                        "reserve shared listener topology",
                        io::Error::other(error),
                    ));
                }
            }
        }

        let mut failure = None;
        for (index, manager) in ordered.iter().enumerate() {
            let socket_slot = manager.socket_slot;
            let should_connect = connected_owner_slot == Some(socket_slot);
            if !matches!(
                prepared.listener_associations[index],
                crate::net::managed_socket::AssociationState::Unconnected { .. }
            ) {
                failure = Some((index, unexpected_association_cause.to_string()));
                break;
            }
            if should_connect {
                prepared.transition_phases[index] = ClientFlowSocketTransitionPhase::Attempted;
                prepared.journal[index].transition_attempted = true;
                let Some(topology) = prepared.topology.get_mut(index).and_then(Option::as_mut)
                else {
                    return Err(transaction_failure(
                        "establish shared client flow",
                        "listener topology reservation disappeared before connect",
                        std::mem::take(&mut prepared.journal),
                    ));
                };
                match topology.connect_unconnected(update.client) {
                    Ok(()) => {
                        prepared.transition_phases[index] =
                            ClientFlowSocketTransitionPhase::Completed;
                        prepared.journal[index].transition_completed = true;
                    }
                    Err(error) => {
                        failure = Some((index, error.to_string()));
                        break;
                    }
                }
            }
        }

        if let Some((failed_index, cause)) = failure.take() {
            return match recover_failed_client_flow_establishment(
                ordered,
                &transaction_guards,
                &prepared.listener_states,
                &mut prepared.topology,
                &mut prepared.capacities,
                &prepared.transition_phases,
                &mut prepared.journal,
                failed_index,
                cause,
            ) {
                Err(error) => Err(error),
                Ok(_) => {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "failed client-flow establishment unexpectedly returned usable state"
                    ));
                    Err(ManagerError::Poisoned {
                        authority: "client-flow establishment recovery",
                    })
                }
            };
        }

        Ok(PreparedClientFlowTransition {
            prepared,
            visibility,
            transaction_guards,
        })
    }

    #[inline]
    pub(super) fn upstream_socket_local_id_request(
        proto: SupportedProtocol,
        source_id_request: IcmpReplyIdRequest,
        reply_id_request: IcmpReplyIdRequest,
    ) -> u16 {
        match proto {
            SupportedProtocol::UDP => source_id_request.requested_socket_id(),
            SupportedProtocol::ICMP => reply_id_request.requested_socket_id(),
        }
    }

    pub(super) fn normalized_upstream_local_after_getsockname(
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
            )
            .local_id
        } else {
            actual_local_addr.port()
        };
        LogicalEndpoint::from_socket_addr_with_id(actual_local_addr, id)
    }
}
