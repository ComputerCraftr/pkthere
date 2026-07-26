use crate::cli::IcmpReplyIdRequest;
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{FlowTuple, SocketLegFlow};
use crate::net::managed_socket::{RetiredTopologyReservation, TopologyReservation};
use pkthere_socket_policy::SocketEvidenceKey;
use pkthere_socket_policy::{ListenerClearStrategy, ListenerLockLifecycle, SocketRole};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use super::transaction_lock::ManagerTransactionGuard;
use super::version::VersionCapacityGuard;
use super::{
    ManagerError, PublishedUpdate, RecoveryOutcome, SocketHandles, TransactionJournalEntry,
};

use super::receiver_slot::ReceiverRole;
use super::state::ClientListenState;

pub(super) fn socket_evidence_json(
    key: SocketEvidenceKey,
    event: &'static str,
    requested: &str,
    kernel_addr: SocketAddr,
) -> serde_json::Value {
    crate::diagnostics::stamp(audited_json!({
        "event": "socket_evidence",
        "action": event,
        "key": socket_evidence_key_json(key),
        "requested": requested,
        "getsockname": kernel_addr.to_string(),
    }))
}

pub(crate) fn socket_evidence_key_json(key: SocketEvidenceKey) -> serde_json::Value {
    audited_json!({
        "process_id": key.process_id,
        "role": match key.role {
            SocketRole::Listener => "listener",
            SocketRole::Upstream => "upstream",
        },
        "domain": if key.domain == socket2::Domain::IPV4 {
            "ipv4"
        } else if key.domain == socket2::Domain::IPV6 {
            "ipv6"
        } else {
            "other"
        },
        "socket_slot": key.socket_slot,
        "generation": key.generation,
    })
}

use super::group_publication::{
    COMPONENT_DESCRIPTOR_ASSOCIATION, COMPONENT_FLOW_VISIBILITY, COMPONENT_MANAGER_METADATA,
    COMPONENT_MANAGER_VERSION, COMPONENT_SOCKET_GATES, CommittedGroupPublication, PublicationStep,
    fail_group_publication, production_group_publication,
};
use super::manager_types::{
    ClientFlowSocketTransitionPhase, PreparedClientFlowGroup, PreparedClientFlowTransition,
    SocketManager,
};

struct EstablishGroupPublication<'borrow, 'manager, 'reservation, 'flow> {
    prepared: &'borrow mut PreparedClientFlowGroup<'manager>,
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
    transaction_guards: Option<super::transaction_lock::ManagerTransactionGuardSet<'manager>>,
    visibility: Option<crate::flow_state::CommittedClientFlowTopology<'reservation, 'flow>>,
}

impl CommittedGroupPublication for EstablishGroupPublication<'_, '_, '_, '_> {
    type Error = ManagerError;
    type Output = Vec<PublishedUpdate>;

    fn publish_receiver(&mut self, _step: PublicationStep<'_, 0>) -> Result<(), Self::Error> {
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
                authority: "client-flow listener publication guards",
            })?;
        let upstream_guards = self
            .upstream_guards
            .as_ref()
            .ok_or(ManagerError::Poisoned {
                authority: "client-flow upstream publication guards",
            })?;
        for index in 0..self.prepared.ordered.len() {
            if !Arc::ptr_eq(
                &listener_guards[index].metadata,
                &self.prepared.listener_states[index].metadata,
            ) || !listener_guards[index]
                .sock
                .same_descriptor(&self.prepared.listener_states[index].sock)
                || !Arc::ptr_eq(
                    &upstream_guards[index].metadata,
                    &self.prepared.upstream_states[index].metadata,
                )
                || !upstream_guards[index]
                    .sock
                    .same_descriptor(&self.prepared.upstream_states[index].sock)
            {
                return Err(ManagerError::Poisoned {
                    authority: "client-flow prepared manager state",
                });
            }
            listener_guards[index].metadata =
                Arc::clone(&self.prepared.published_listener_metadata[index]);
        }
        Ok(())
    }

    fn publish_manager(
        &mut self,
        _step: PublicationStep<'_, 2>,
        index: usize,
    ) -> Result<(), Self::Error> {
        let manager = self.prepared.ordered[index];
        let capacity = self
            .prepared
            .capacities
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(ManagerError::Poisoned {
                authority: "prechecked version ownership",
            })?;
        let transaction_guards =
            self.transaction_guards
                .as_ref()
                .ok_or(ManagerError::Poisoned {
                    authority: "client-flow manager reservations",
                })?;
        let version = manager.publish_prechecked(&transaction_guards[index], capacity)?;
        let listener_guards = self
            .listener_guards
            .as_ref()
            .ok_or(ManagerError::Poisoned {
                authority: "client-flow listener publication guards",
            })?;
        let upstream_guards = self
            .upstream_guards
            .as_ref()
            .ok_or(ManagerError::Poisoned {
                authority: "client-flow upstream publication guards",
            })?;
        self.prepared
            .published
            .push(PublishedUpdate::new(SocketHandles {
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
        for reservation in std::mem::take(&mut self.prepared.topology)
            .into_iter()
            .rev()
        {
            let reservation = reservation.ok_or(ManagerError::Poisoned {
                authority: "listener topology ownership",
            })?;
            reservation.commit().map_err(|error| {
                ManagerError::io(
                    "publish listener topology reservation",
                    std::io::Error::other(error),
                )
            })?;
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
                authority: "client-flow manager reservations",
            })?
            .commit_all()
            .map_err(|cause| ManagerError::Reservation {
                operation: "commit grouped manager publication",
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
                authority: "client-flow visibility reservation",
            })?
            .publish()
            .map_err(|error| {
                ManagerError::io(
                    "publish client-flow visibility",
                    std::io::Error::other(error),
                )
            })
    }

    fn finish(self, _step: PublicationStep<'_, 6>) -> Self::Output {
        std::mem::take(&mut self.prepared.published)
    }
}

#[inline]
pub(super) fn upstream_leg_flow(
    local_reply: LogicalEndpoint,
    local_source_id_request: IcmpReplyIdRequest,
    remote: LogicalEndpoint,
) -> SocketLegFlow {
    let source_id = local_source_id_request
        .resolved_reply_id(local_reply.id())
        .unwrap_or_else(|| local_reply.id());
    let local_source = local_reply.with_id(source_id);
    SocketLegFlow::new(
        Some(FlowTuple::new(remote, local_reply)),
        Some(FlowTuple::new(local_source, remote)),
    )
}

pub(super) fn lock_manager_authority<'a, T>(
    mutex: &'a crate::authority::AuthorityMutex<crate::authority::tags::ManagerState, T>,
    authority: &'static str,
) -> Result<
    crate::authority::AuthorityMutexGuard<'a, crate::authority::tags::ManagerState, T>,
    ManagerError,
> {
    mutex.lock().map_err(|error| {
        crate::runtime_support::publish_process_fatal(format_args!(
            "{authority} authority acquisition failed: {error}"
        ));
        ManagerError::Poisoned { authority }
    })
}

pub(super) fn lock_manager_authorities<'a, T>(
    mutexes: impl IntoIterator<
        Item = &'a crate::authority::AuthorityMutex<crate::authority::tags::ManagerState, T>,
    >,
    authority: &'static str,
) -> Result<
    crate::authority::AuthorityMutexGuardSet<'a, crate::authority::tags::ManagerState, T>,
    ManagerError,
> {
    crate::authority::AuthorityMutexGuardSet::collect_ordered(
        mutexes
            .into_iter()
            .map(|mutex| lock_manager_authority(mutex, authority)),
    )
}

pub(super) fn transaction_failure(
    operation: &'static str,
    cause: &'static str,
    journal: Vec<TransactionJournalEntry>,
) -> ManagerError {
    ManagerError::TransactionFailed {
        operation,
        cause: cause.to_string(),
        journal,
    }
}

pub(super) fn reserved_vec<T>(
    capacity: usize,
    operation: &'static str,
) -> Result<Vec<T>, ManagerError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|source| ManagerError::io(operation, io::Error::other(source)))?;
    Ok(values)
}

pub(super) fn apply_listener_clear_strategies(
    ordered: &[&SocketManager],
    states: &mut [ClientListenState],
    was_connected: &[bool],
    topology: &mut [Option<TopologyReservation>],
    retired_topology: &mut [Option<RetiredTopologyReservation>],
    journal: &mut Vec<TransactionJournalEntry>,
    replacements: &mut [Option<TopologyReservation>],
) -> Result<(), ManagerError> {
    crate::net::managed_socket::park_topology_reservation_batch(topology).map_err(|error| {
        ManagerError::io(
            "park shared listener topology batch",
            io::Error::other(error),
        )
    })?;
    // Retire every listener that requires replacement before binding any new
    // member of the reuse-port group. Interleaving retirement and bind leaves
    // Darwin with a mixture of old connected PCBs and a new same-bind member,
    // which can intermittently reject the first replacement with EADDRINUSE.
    // Every topology gate is already closed, so this remains one fail-closed
    // group transaction with no packet-visible intermediate state.
    for index in 0..ordered.len() {
        let lifecycle = states[index].policy.listener_lifecycle;
        let replace_on_clear = matches!(
            lifecycle,
            Some(ListenerLockLifecycle::StayUnconnectedReplaceOnClear)
                | Some(ListenerLockLifecycle::Connected {
                    clear: ListenerClearStrategy::ReplaceOwnerSameBind,
                })
        );
        if !replace_on_clear {
            continue;
        }
        journal[index].transition_attempted = true;
        let result = topology
            .get_mut(index)
            .and_then(Option::take)
            .ok_or_else(|| {
                io::Error::other("listener replacement lost its old topology reservation")
            })
            .and_then(|reservation| {
                reservation
                    .into_retired_for_replacement()
                    .map_err(io::Error::other)
            });
        match result {
            Ok(reservation) => retired_topology[index] = Some(reservation),
            Err(error) => {
                journal[index].recovery = RecoveryOutcome::Failed;
                return fail_listener_clear_transaction(
                    error.to_string(),
                    topology,
                    retired_topology,
                    journal,
                    replacements,
                );
            }
        }
    }
    for index in 0..ordered.len() {
        let lifecycle = states[index].policy.listener_lifecycle;
        let replace_on_clear = matches!(
            lifecycle,
            Some(ListenerLockLifecycle::StayUnconnectedReplaceOnClear)
                | Some(ListenerLockLifecycle::Connected {
                    clear: ListenerClearStrategy::ReplaceOwnerSameBind,
                })
        );
        let descriptor_retired = retired_topology
            .get(index)
            .and_then(Option::as_ref)
            .is_some();
        if replace_on_clear && !descriptor_retired {
            journal[index].recovery = RecoveryOutcome::Failed;
            return fail_listener_clear_transaction(
                "listener replacement group retained an old descriptor".to_string(),
                topology,
                retired_topology,
                journal,
                replacements,
            );
        }
    }

    for index in 0..ordered.len() {
        let state = &mut states[index];
        let lifecycle = state.policy.listener_lifecycle;
        let replace_on_clear = matches!(
            lifecycle,
            Some(ListenerLockLifecycle::StayUnconnectedReplaceOnClear)
                | Some(ListenerLockLifecycle::Connected {
                    clear: ListenerClearStrategy::ReplaceOwnerSameBind,
                })
        );
        if !was_connected[index] && !replace_on_clear {
            continue;
        }
        if !replace_on_clear {
            journal[index].transition_attempted = true;
        }
        let result = match lifecycle {
            Some(ListenerLockLifecycle::StayUnconnectedReplaceOnClear)
            | Some(ListenerLockLifecycle::Connected {
                clear: ListenerClearStrategy::ReplaceOwnerSameBind,
            }) => ordered[index]
                .build_listener_replacement_on_clear(state)
                .map(|publication_gate| {
                    replacements[index] = Some(publication_gate);
                    journal[index].recovery = RecoveryOutcome::Replaced;
                    journal[index].forced_replacement = true;
                }),
            Some(ListenerLockLifecycle::Connected {
                clear: ListenerClearStrategy::DisconnectToOriginalBind,
            }) => topology
                .get_mut(index)
                .and_then(Option::as_mut)
                .ok_or_else(|| io::Error::other("listener clear lost its topology reservation"))
                .and_then(|reservation| {
                    reservation.disconnect_connected().map_err(io::Error::other)
                }),
            Some(ListenerLockLifecycle::Connected {
                clear: ListenerClearStrategy::ProcessExit,
            }) => Err(io::Error::other(
                "listener clear was requested for a process-exit-only connected socket",
            )),
            Some(ListenerLockLifecycle::StayUnconnected) | None => {
                if was_connected[index] {
                    Err(io::Error::other(
                        "listener was connected despite a stay-unconnected lifecycle policy",
                    ))
                } else {
                    Ok(())
                }
            }
        };
        match result {
            Ok(()) => journal[index].transition_completed = true,
            Err(error) => {
                journal[index].recovery = RecoveryOutcome::Failed;
                return fail_listener_clear_transaction(
                    error.to_string(),
                    topology,
                    retired_topology,
                    journal,
                    replacements,
                );
            }
        }
    }
    Ok(())
}

pub(super) fn fail_listener_clear_transaction(
    mut cause: String,
    topology: &mut [Option<TopologyReservation>],
    retired_topology: &mut [Option<RetiredTopologyReservation>],
    journal: &mut Vec<TransactionJournalEntry>,
    replacements: &mut [Option<TopologyReservation>],
) -> Result<(), ManagerError> {
    for reservation in replacements.iter_mut().rev().filter_map(Option::take) {
        if let Err(error) = reservation.rollback() {
            cause.push_str(&format!("; replacement rollback failed: {error}"));
        }
    }
    for reservation in retired_topology.iter_mut().rev().filter_map(Option::take) {
        if let Err(error) = reservation.commit() {
            cause.push_str(&format!("; retired topology finalization failed: {error}"));
        }
    }
    for reservation in topology.iter_mut().rev().filter_map(Option::take) {
        let result = reservation.finish_failed_transition();
        if let Err(error) = result {
            cause.push_str(&format!("; failed topology finalization failed: {error}"));
        }
    }
    Err(ManagerError::TransactionFailed {
        operation: "clear shared client flow",
        cause,
        journal: std::mem::take(journal),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn recover_failed_client_flow_establishment(
    ordered: &[&SocketManager],
    transaction_guards: &[ManagerTransactionGuard<'_>],
    listener_states: &[ClientListenState],
    topology: &mut [Option<TopologyReservation>],
    capacities: &mut [Option<VersionCapacityGuard>],
    transition_phases: &[ClientFlowSocketTransitionPhase],
    journal: &mut Vec<TransactionJournalEntry>,
    failed_index: usize,
    mut cause: String,
) -> Result<Vec<PublishedUpdate>, ManagerError> {
    let mut recovery_states = listener_states.to_vec();
    let mut replacements = vec![false; ordered.len()];
    for index in (0..ordered.len()).rev() {
        let manager = ordered[index];
        let state = &mut recovery_states[index];
        let Some(reservation) = topology[index].take() else {
            continue;
        };
        if reservation.rollback().is_ok() {
            if index > failed_index
                || transition_phases[index] == ClientFlowSocketTransitionPhase::Reserved
            {
                journal[index].recovery = RecoveryOutcome::NotRequired;
            } else {
                journal[index].recovery = RecoveryOutcome::Restored;
            }
            continue;
        }
        if index > failed_index {
            cause = format!(
                "{cause}; topology rollback also failed for untouched slot {}",
                manager.socket_slot
            );
        }
        if manager
            .replace_listener_after_transition_failure(state)
            .is_ok()
        {
            journal[index].recovery = RecoveryOutcome::Replaced;
            journal[index].forced_replacement = true;
            replacements[index] = true;
        } else {
            journal[index].recovery = RecoveryOutcome::Failed;
            cause = format!(
                "{cause}; topology rollback and listener replacement failed for slot {}",
                manager.socket_slot
            );
        }
    }
    let mut listener_guards = lock_manager_authorities(
        ordered.iter().map(|manager| &manager.client_listen),
        "listener manager",
    )?;
    for index in 0..ordered.len() {
        if !replacements[index] {
            continue;
        }
        ordered[index]
            .publish_receiver_socket(ReceiverRole::Listener, &recovery_states[index].sock)?;
        *listener_guards[index] = recovery_states[index].clone();
        let Some(capacity) = capacities.get_mut(index).and_then(Option::take) else {
            return Err(transaction_failure(
                "recover shared client flow",
                "replacement manager lost its prechecked version capacity",
                std::mem::take(journal),
            ));
        };
        let version = ordered[index].publish_prechecked(&transaction_guards[index], capacity)?;
        journal[index].recovery_version = Some(version);
    }
    Err(ManagerError::TransactionFailed {
        operation: "establish shared client flow",
        cause,
        journal: std::mem::take(journal),
    })
}

impl PreparedClientFlowTransition<'_, '_, '_> {
    pub(crate) fn abort(mut self, cause: String) -> Result<Vec<PublishedUpdate>, ManagerError> {
        let failed_index = self.prepared.ordered.len().saturating_sub(1);
        recover_failed_client_flow_establishment(
            &self.prepared.ordered,
            &self.transaction_guards,
            &self.prepared.listener_states,
            &mut self.prepared.topology,
            &mut self.prepared.capacities,
            &self.prepared.transition_phases,
            &mut self.prepared.journal,
            failed_index,
            cause,
        )
    }

    pub(crate) fn publish(
        mut self,
        flow_claim_generation: Option<std::num::NonZeroU64>,
    ) -> Result<Vec<PublishedUpdate>, ManagerError> {
        let prepared = &mut self.prepared;
        let ordered = &prepared.ordered;
        let update = prepared.update;
        let socket_applied = if let Ok(applied) = self.visibility.socket_transitions_applied() {
            applied
        } else {
            return Err(ManagerError::TransactionFailed {
                operation: "establish shared client flow",
                cause: "could not advance flow-topology transaction".to_string(),
                journal: std::mem::take(&mut prepared.journal),
            });
        };
        let manager_prepared =
            if let Ok(prepared_topology) = socket_applied.manager_state_prepared() {
                prepared_topology
            } else {
                return Err(ManagerError::TransactionFailed {
                    operation: "establish shared client flow",
                    cause: "could not stage flow-topology transaction".to_string(),
                    journal: std::mem::take(&mut prepared.journal),
                });
            };
        let visibility = match manager_prepared.commit_session_with(|flow| {
            flow.publish_locked_with_claim(update.flow, flow_claim_generation)
        }) {
            Ok((visibility, ())) => visibility,
            Err(error) => {
                return Err(ManagerError::TransactionFailed {
                    operation: "establish shared client flow",
                    cause: format!("could not commit flow session state: {error}"),
                    journal: std::mem::take(&mut prepared.journal),
                });
            }
        };
        let publication = production_group_publication(
            ordered.len(),
            COMPONENT_DESCRIPTOR_ASSOCIATION
                | COMPONENT_MANAGER_METADATA
                | COMPONENT_MANAGER_VERSION
                | COMPONENT_SOCKET_GATES
                | COMPONENT_FLOW_VISIBILITY,
        )
        .map_err(|error| group_publication_failure("initialization", error))?;

        let listener_guards = crate::authority::AuthorityMutexGuardSet::collect_ordered_into(
            std::mem::take(&mut prepared.listener_guard_storage),
            ordered
                .iter()
                .map(|manager| &manager.client_listen)
                .map(|mutex| lock_manager_authority(mutex, "listener manager")),
        )
        .map_err(|error| group_publication_failure("listener lock reacquisition", error))?;
        let upstream_guards = crate::authority::AuthorityMutexGuardSet::collect_ordered_into(
            std::mem::take(&mut prepared.upstream_guard_storage),
            ordered
                .iter()
                .map(|manager| &manager.upstream_state)
                .map(|mutex| lock_manager_authority(mutex, "upstream manager")),
        )
        .map_err(|error| group_publication_failure("upstream lock reacquisition", error))?;
        publication
            .publish_committed(EstablishGroupPublication {
                prepared,
                listener_guards: Some(listener_guards),
                upstream_guards: Some(upstream_guards),
                transaction_guards: Some(self.transaction_guards),
                visibility: Some(visibility),
            })
            .map_err(|error| group_publication_failure("committed publication", error))
    }
}

fn group_publication_failure(operation: &'static str, error: impl std::fmt::Debug) -> ManagerError {
    fail_group_publication(operation, error)
}
