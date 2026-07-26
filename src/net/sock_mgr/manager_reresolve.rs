use super::manager::reserved_vec;
use super::manager_types::{ReresolveSummary, SocketManager};
use crate::endpoint::LogicalEndpoint;
use crate::net::managed_socket::{
    AssociationOperation, ManagedSocket, ManagedSocketError, ReplacementBoundTopologyReservation,
    RetiredTopologyReservation, TopologyReservation, TopologyReservationBatch,
};
use crate::net::sock_mgr::manager::socket_evidence_json;
use crate::net::sock_mgr::state::{
    ClientListenState, ListenerMetadata, ReresolveAction, SocketUpdateKind, UpstreamMetadata,
    UpstreamState, decide_listener_endpoint_update, decide_upstream_endpoint_update,
};
use crate::net::sock_mgr::transaction_lock::ManagerTransactionGuardSet;
use crate::net::sock_mgr::{ManagerError, ReceiverRole, SocketHandles, TransactionJournalEntry};
use crate::net::socket::resolve_first;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

pub(super) struct PreparedListenerReplacement {
    pub(super) socket: ManagedSocket,
    pub(super) metadata: Arc<ListenerMetadata>,
    pub(super) update: SocketUpdateKind,
    pub(super) publication_gate: TopologyReservation,
}

pub(super) struct AppliedListenerPlan {
    pub(super) replacement: Option<PreparedListenerReplacement>,
}

impl AppliedListenerPlan {
    pub(super) const fn unchanged() -> Self {
        Self { replacement: None }
    }

    pub(super) fn replacement(replacement: PreparedListenerReplacement) -> Self {
        Self {
            replacement: Some(replacement),
        }
    }
}

pub(super) enum ListenerReresolvePlan {
    Unchanged,
    Replace {
        destination: LogicalEndpoint,
        update: SocketUpdateKind,
    },
}

pub(super) struct PreparedUpstreamReplacement {
    pub(super) socket: ManagedSocket,
    pub(super) metadata: Arc<UpstreamMetadata>,
    pub(super) update: SocketUpdateKind,
    pub(super) publication_gate: TopologyReservation,
}

pub(super) enum UpstreamReresolvePlan {
    Unchanged,
    Metadata(Arc<UpstreamMetadata>),
    Reconnect { destination: LogicalEndpoint },
    Replace { destination: LogicalEndpoint },
}

pub(super) struct AppliedUpstreamPlan {
    pub(super) socket: Option<ManagedSocket>,
    pub(super) metadata: Option<Arc<UpstreamMetadata>>,
    pub(super) update: SocketUpdateKind,
    /// Executable transition state. Journal fields are diagnostics only.
    pub(super) journal: TransactionJournalEntry,
    pub(super) publication_gate: Option<TopologyReservation>,
}

pub(super) struct GroupTopologyReservations {
    pub(super) listener: Vec<Option<TopologyReservation>>,
    pub(super) upstream: Vec<Option<TopologyReservation>>,
    pub(super) retired_listener: Vec<Option<RetiredTopologyReservation>>,
    pub(super) retired_upstream: Vec<Option<RetiredTopologyReservation>>,
}

pub(super) struct PreparedGroupTopologyStorage {
    reservations: GroupTopologyReservations,
    acquired: TopologyReservationBatch<AcquiredGroupTopology>,
}

pub(super) struct GroupPlanApplication<'a> {
    pub(super) ordered: &'a [&'a SocketManager],
    pub(super) listener_snapshots: &'a [ClientListenState],
    pub(super) upstream_snapshots: &'a [UpstreamState],
    pub(super) listener_plans: Vec<ListenerReresolvePlan>,
    pub(super) upstream_plans: Vec<UpstreamReresolvePlan>,
    pub(super) upstream_topology: &'a mut [Option<TopologyReservation>],
    pub(super) retired_listener_topology: &'a mut [Option<RetiredTopologyReservation>],
    pub(super) retired_upstream_topology: &'a mut [Option<RetiredTopologyReservation>],
    pub(super) bound_listener_topology: &'a mut [Option<ReplacementBoundTopologyReservation>],
    pub(super) bound_upstream_topology: &'a mut [Option<ReplacementBoundTopologyReservation>],
}

pub(crate) struct PreparedReresolveGroup<'manager> {
    pub(super) ordered: Vec<&'manager SocketManager>,
    pub(super) summaries: Vec<ReresolveSummary>,
    pub(super) listener_states: Vec<ClientListenState>,
    pub(super) upstream_states: Vec<UpstreamState>,
    pub(super) capacities: Vec<Option<super::version::VersionCapacityGuard>>,
    pub(super) listener_receivers:
        Vec<Option<(ManagedSocket, crate::net::managed_socket::ManagedReceiver)>>,
    pub(super) upstream_receivers:
        Vec<Option<(ManagedSocket, crate::net::managed_socket::ManagedReceiver)>>,
    pub(super) listener_topology: Vec<Option<TopologyReservation>>,
    pub(super) upstream_topology: Vec<Option<TopologyReservation>>,
    pub(super) retired_listener_topology: Vec<Option<ReplacementBoundTopologyReservation>>,
    pub(super) retired_upstream_topology: Vec<Option<ReplacementBoundTopologyReservation>>,
    pub(super) listener_publication: Vec<Option<TopologyReservation>>,
    pub(super) upstream_publication: Vec<Option<TopologyReservation>>,
    pub(super) transactions: ManagerTransactionGuardSet<'manager>,
    pub(super) listener_guard_storage: Vec<
        crate::authority::AuthorityMutexGuard<
            'manager,
            crate::authority::tags::ManagerState,
            ClientListenState,
        >,
    >,
    pub(super) upstream_guard_storage: Vec<
        crate::authority::AuthorityMutexGuard<
            'manager,
            crate::authority::tags::ManagerState,
            UpstreamState,
        >,
    >,
}

enum AcquiredGroupTopology {
    Listener {
        index: usize,
        reservation: TopologyReservation,
    },
    Upstream {
        index: usize,
        replace: bool,
        reservation: TopologyReservation,
    },
}

fn rollback_group_topology_reservations(
    acquired: TopologyReservationBatch<AcquiredGroupTopology>,
) -> Option<ManagedSocketError> {
    acquired.rollback_reverse(|_step, acquired| match acquired {
        AcquiredGroupTopology::Listener { reservation, .. }
        | AcquiredGroupTopology::Upstream { reservation, .. } => reservation.rollback(),
    })
}

pub(super) fn grouped_topology_reservation_error(
    operation: &'static str,
    source: ManagedSocketError,
    rollback_error: Option<ManagedSocketError>,
) -> ManagerError {
    let cause = match rollback_error {
        Some(rollback_error) => {
            format!("{source}; prior topology rollback also failed: {rollback_error}")
        }
        None => source.to_string(),
    };
    ManagerError::io(operation, io::Error::other(cause))
}

pub(super) fn validate_group_plan_consistency(
    listener_updates: &[SocketUpdateKind],
    applied_upstreams: Vec<AppliedUpstreamPlan>,
    changed: &[bool],
) -> Result<Vec<AppliedUpstreamPlan>, ManagerError> {
    let is_consistent = listener_updates
        .iter()
        .zip(&applied_upstreams)
        .zip(changed)
        .all(|((listener_update, applied), expected_changed)| {
            (listener_update.changed() || applied.update.changed()) == *expected_changed
        });
    if is_consistent {
        return Ok(applied_upstreams);
    }
    Err(ManagerError::TransactionFailed {
        operation: "publish grouped re-resolution",
        cause: "re-resolution plan changed before manager publication".to_string(),
        journal: applied_upstreams
            .into_iter()
            .map(|applied| applied.journal)
            .collect(),
    })
}

pub(super) fn commit_group_topology(
    mut listener_topology: Vec<Option<TopologyReservation>>,
    mut upstream_topology: Vec<Option<TopologyReservation>>,
    mut retired_listener_topology: Vec<Option<ReplacementBoundTopologyReservation>>,
    mut retired_upstream_topology: Vec<Option<ReplacementBoundTopologyReservation>>,
    mut listener_publication: Vec<Option<TopologyReservation>>,
    mut upstream_publication: Vec<Option<TopologyReservation>>,
    transactions: ManagerTransactionGuardSet<'_>,
) -> Result<(), ManagerError> {
    for index in (0..listener_publication.len()).rev() {
        if let Some(reservation) = listener_publication[index].take() {
            reservation.commit_publication().map_err(|error| {
                ManagerError::io(
                    "activate grouped listener replacement",
                    io::Error::other(error),
                )
            })?;
        }
    }
    for index in (0..upstream_publication.len()).rev() {
        if let Some(reservation) = upstream_publication[index].take() {
            reservation.commit_publication().map_err(|error| {
                ManagerError::io(
                    "activate grouped upstream replacement",
                    io::Error::other(error),
                )
            })?;
        }
    }
    for index in (0..upstream_topology.len()).rev() {
        if let Some(reservation) = retired_upstream_topology[index].take() {
            reservation.commit().map_err(|error| {
                ManagerError::io(
                    "publish retired grouped upstream topology",
                    io::Error::other(error),
                )
            })?;
        }
        if let Some(reservation) = upstream_topology[index].take() {
            reservation.commit().map_err(|error| {
                ManagerError::io("publish grouped upstream topology", io::Error::other(error))
            })?;
        }
        if let Some(reservation) = retired_listener_topology[index].take() {
            reservation.commit().map_err(|error| {
                ManagerError::io(
                    "publish retired grouped listener topology",
                    io::Error::other(error),
                )
            })?;
        }
        if let Some(reservation) = listener_topology[index].take() {
            reservation.commit().map_err(|error| {
                ManagerError::io("publish grouped listener topology", io::Error::other(error))
            })?;
        }
    }
    transactions
        .commit_all()
        .map_err(|cause| ManagerError::Reservation {
            operation: "complete grouped re-resolution",
            cause,
        })?;
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct ResolvedReresolveAddresses {
    pub(super) listener: Option<SocketAddr>,
    pub(super) upstream: Option<SocketAddr>,
}

pub(super) fn resolve_group_addresses(
    managers: &[&SocketManager],
    allow_upstream: bool,
    allow_listen_rebind: bool,
    listen_addr: Option<SocketAddr>,
    upstream_addr: Option<SocketAddr>,
) -> Result<Vec<ResolvedReresolveAddresses>, ManagerError> {
    managers
        .iter()
        .map(|manager| {
            let listener = if allow_listen_rebind {
                Some(match listen_addr {
                    Some(address) => address,
                    None => resolve_first(&manager.listen_target)
                        .map_err(|error| ManagerError::io("resolve listener", error))?,
                })
            } else {
                None
            };
            let upstream = if allow_upstream {
                Some(match upstream_addr {
                    Some(address) => address,
                    None => resolve_first(&manager.upstream_target)
                        .map_err(|error| ManagerError::io("resolve upstream", error))?,
                })
            } else {
                None
            };
            Ok(ResolvedReresolveAddresses { listener, upstream })
        })
        .collect()
}

pub(super) fn precheck_group_receiver_publication(
    managers: &[&SocketManager],
) -> Result<(), ManagerError> {
    managers.iter().try_for_each(|manager| {
        manager.precheck_receiver_publication(ReceiverRole::Listener)?;
        manager.precheck_receiver_publication(ReceiverRole::Upstream)
    })
}

pub(super) fn manager_reresolve_changed(
    listener: &ClientListenState,
    upstream: &UpstreamState,
    resolved: ResolvedReresolveAddresses,
    preserve_listener_id: bool,
    preserve_upstream_id: bool,
) -> bool {
    let listener_changed = resolved.listener.is_some_and(|address| {
        let fresh = if preserve_listener_id {
            listener.listen_local_filter.with_resolved_ip(address)
        } else {
            LogicalEndpoint::from_socket_addr(address)
        };
        decide_listener_endpoint_update(listener.listen_local_filter, fresh).1
            != ReresolveAction::NoChange
    });
    let upstream_changed = resolved.upstream.is_some_and(|address| {
        let fresh = if preserve_upstream_id {
            upstream.upstream_remote_filter.with_resolved_ip(address)
        } else {
            LogicalEndpoint::from_socket_addr(address)
        };
        decide_upstream_endpoint_update(
            upstream.upstream_remote_filter,
            fresh,
            upstream.sock.is_connected(),
            upstream.policy,
        )
        .1 != ReresolveAction::NoChange
    });
    listener_changed || upstream_changed
}

pub(super) fn reserve_group_topology(
    ordered: &[&SocketManager],
    listener_snapshots: &[ClientListenState],
    upstream_snapshots: &[UpstreamState],
    listener_plans: &[ListenerReresolvePlan],
    upstream_plans: &[UpstreamReresolvePlan],
    storage: PreparedGroupTopologyStorage,
) -> Result<GroupTopologyReservations, ManagerError> {
    let PreparedGroupTopologyStorage {
        mut reservations,
        mut acquired,
    } = storage;
    for index in 0..ordered.len() {
        if matches!(listener_plans[index], ListenerReresolvePlan::Replace { .. }) {
            match listener_snapshots[index]
                .sock
                .reserve_topology(AssociationOperation::Replace)
            {
                Ok(reservation) => {
                    acquired.push(AcquiredGroupTopology::Listener { index, reservation });
                }
                Err(source) => {
                    let rollback_error = rollback_group_topology_reservations(acquired);
                    return Err(grouped_topology_reservation_error(
                        "reserve grouped listener topology",
                        source,
                        rollback_error,
                    ));
                }
            }
        }
        if !matches!(upstream_plans[index], UpstreamReresolvePlan::Unchanged) {
            let operation = if matches!(
                upstream_plans[index],
                UpstreamReresolvePlan::Reconnect { .. }
            ) {
                AssociationOperation::Reconnect
            } else {
                AssociationOperation::Replace
            };
            match upstream_snapshots[index].sock.reserve_topology(operation) {
                Ok(reservation) => {
                    acquired.push(AcquiredGroupTopology::Upstream {
                        index,
                        replace: matches!(
                            upstream_plans[index],
                            UpstreamReresolvePlan::Replace { .. }
                        ),
                        reservation,
                    });
                }
                Err(source) => {
                    let rollback_error = rollback_group_topology_reservations(acquired);
                    return Err(grouped_topology_reservation_error(
                        "reserve grouped upstream topology",
                        source,
                        rollback_error,
                    ));
                }
            }
        }
    }
    // Dynamic authority scopes are stack-disciplined. Park or retire every
    // old-socket reservation in exact reverse acquisition order before any
    // replacement socket publishes its own closed topology gate.
    if let Err(failure) = acquired.try_finish_reverse(|step, acquired| match acquired {
        AcquiredGroupTopology::Listener { index, reservation } => {
            let reservation = reservation.into_retired_for_replacement()?;
            reservations.retired_listener[index] = Some(reservation);
            Ok(())
        }
        AcquiredGroupTopology::Upstream {
            index,
            replace,
            mut reservation,
        } => {
            if replace {
                let reservation = reservation.into_retired_for_replacement()?;
                reservations.retired_upstream[index] = Some(reservation);
            } else {
                reservation.park_authority(step)?;
                reservations.upstream[index] = Some(reservation);
            }
            Ok(())
        }
    }) {
        let rollback_error = rollback_group_topology_reservations(failure.remaining);
        return Err(grouped_topology_reservation_error(
            "park grouped topology reservations",
            failure.source,
            rollback_error,
        ));
    }
    Ok(reservations)
}

pub(super) fn prepare_group_topology_storage(
    manager_count: usize,
) -> Result<PreparedGroupTopologyStorage, ManagerError> {
    let acquired_capacity = manager_count.checked_mul(2).ok_or_else(|| {
        ManagerError::io(
            "prepare grouped topology reservations",
            io::Error::other("grouped topology reservation capacity overflow"),
        )
    })?;
    let mut listener_topology = reserved_vec(
        manager_count,
        "prepare grouped listener topology reservations",
    )?;
    let mut upstream_topology = reserved_vec(
        manager_count,
        "prepare grouped upstream topology reservations",
    )?;
    let acquired =
        TopologyReservationBatch::try_with_capacity(acquired_capacity).map_err(|source| {
            ManagerError::io(
                "prepare grouped topology rollback journal",
                io::Error::other(source),
            )
        })?;
    listener_topology.resize_with(manager_count, || None);
    upstream_topology.resize_with(manager_count, || None);
    let mut retired_listener = reserved_vec(
        manager_count,
        "prepare grouped retired listener topology reservations",
    )?;
    let mut retired_upstream = reserved_vec(
        manager_count,
        "prepare grouped retired upstream topology reservations",
    )?;
    retired_listener.resize_with(manager_count, || None);
    retired_upstream.resize_with(manager_count, || None);
    Ok(PreparedGroupTopologyStorage {
        reservations: GroupTopologyReservations {
            listener: listener_topology,
            upstream: upstream_topology,
            retired_listener,
            retired_upstream,
        },
        acquired,
    })
}

pub(super) fn apply_group_plans(
    application: GroupPlanApplication<'_>,
    mut applied_listeners: Vec<AppliedListenerPlan>,
    mut applied_upstreams: Vec<AppliedUpstreamPlan>,
) -> Result<(Vec<AppliedListenerPlan>, Vec<AppliedUpstreamPlan>), ManagerError> {
    let GroupPlanApplication {
        ordered,
        listener_snapshots,
        upstream_snapshots,
        listener_plans,
        upstream_plans,
        upstream_topology,
        retired_listener_topology,
        retired_upstream_topology,
        bound_listener_topology,
        bound_upstream_topology,
    } = application;
    for (index, (listener_plan, upstream_plan)) in
        listener_plans.into_iter().zip(upstream_plans).enumerate()
    {
        let manager = ordered[index];
        let applied_listener = match listener_plan {
            ListenerReresolvePlan::Unchanged => AppliedListenerPlan::unchanged(),
            ListenerReresolvePlan::Replace {
                destination,
                update,
            } => {
                let retired = retired_listener_topology[index].take().ok_or_else(|| {
                    ManagerError::io(
                        "record bound listener replacement",
                        io::Error::other("retired listener topology was not retained"),
                    )
                })?;
                let replacement = manager
                    .build_listener_replacement(&listener_snapshots[index], destination, update)
                    .map_err(|error| {
                        ManagerError::io("prepare listener replacement after quiescence", error)
                    })?;
                bound_listener_topology[index] =
                    Some(retired.replacement_bound().map_err(|error| {
                        ManagerError::io(
                            "record bound listener replacement",
                            io::Error::other(error),
                        )
                    })?);
                AppliedListenerPlan::replacement(replacement)
            }
        };
        applied_listeners.push(applied_listener);

        let applied_upstream = manager.apply_upstream_reresolve(
            &upstream_snapshots[index],
            upstream_plan,
            &mut upstream_topology[index],
            &mut retired_upstream_topology[index],
            &mut bound_upstream_topology[index],
        )?;
        applied_upstreams.push(applied_upstream);
    }
    Ok((applied_listeners, applied_upstreams))
}

impl PreparedReresolveGroup<'_> {
    pub(crate) fn summaries(&self) -> &[ReresolveSummary] {
        &self.summaries
    }

    pub(crate) fn publish(mut self) -> Result<Vec<ReresolveSummary>, ManagerError> {
        for index in 0..self.ordered.len() {
            if let Some((socket, receiver)) = self.listener_receivers[index].take() {
                self.ordered[index].publish_staged_receiver(
                    ReceiverRole::Listener,
                    &socket,
                    receiver,
                )?;
            }
            if let Some((socket, receiver)) = self.upstream_receivers[index].take() {
                self.ordered[index].publish_staged_receiver(
                    ReceiverRole::Upstream,
                    &socket,
                    receiver,
                )?;
            }
        }
        let mut listeners = crate::authority::AuthorityMutexGuardSet::collect_ordered_into(
            std::mem::take(&mut self.listener_guard_storage),
            self.ordered.iter().map(|manager| {
                super::manager::lock_manager_authority(&manager.client_listen, "listener manager")
            }),
        )?;
        let mut upstreams = crate::authority::AuthorityMutexGuardSet::collect_ordered_into(
            std::mem::take(&mut self.upstream_guard_storage),
            self.ordered.iter().map(|manager| {
                super::manager::lock_manager_authority(&manager.upstream_state, "upstream manager")
            }),
        )?;
        for index in 0..self.ordered.len() {
            *listeners[index] = self.listener_states[index].clone();
            *upstreams[index] = self.upstream_states[index].clone();
            let version = match self.capacities[index].take() {
                Some(capacity) => {
                    self.ordered[index].publish_prechecked(&self.transactions[index], capacity)?
                }
                None => self.ordered[index].version.current(),
            };
            self.summaries[index].handles = SocketHandles {
                listener: Arc::clone(&listeners[index].metadata),
                client_sock: listeners[index].sock.clone(),
                upstream: Arc::clone(&upstreams[index].metadata),
                upstream_sock: upstreams[index].sock.clone(),
                version,
            };
        }
        drop(upstreams);
        drop(listeners);
        commit_group_topology(
            self.listener_topology,
            self.upstream_topology,
            self.retired_listener_topology,
            self.retired_upstream_topology,
            self.listener_publication,
            self.upstream_publication,
            self.transactions,
        )?;
        Ok(self.summaries)
    }
}

impl SocketManager {
    pub(crate) fn log_reresolve_summary(&self, context: &str, summary: &ReresolveSummary) {
        if summary.listener_update.changed() {
            log_info!(
                "{context}: listen {} ({})",
                summary.handles.listener.listen_local_filter,
                summary.listener_update.wire_name()
            );
            if self.debug_handles {
                log_debug!(
                    true,
                    "socket-evidence {}",
                    socket_evidence_json(
                        summary.handles.listener.evidence_key,
                        summary.listener_update.wire_name(),
                        &self.listen_target,
                        summary.handles.listener.listen_local_kernel_addr,
                    )
                );
            }
        }
        if summary.upstream_update.changed() {
            log_info!(
                "{context}: upstream {} ({})",
                summary.handles.upstream.upstream_remote_filter,
                summary.upstream_update.wire_name()
            );
            if self.debug_handles {
                log_debug!(
                    true,
                    "socket-evidence {}",
                    socket_evidence_json(
                        summary.handles.upstream.evidence_key,
                        summary.upstream_update.wire_name(),
                        &self.upstream_target,
                        summary.handles.upstream.upstream_local_kernel_addr,
                    )
                );
            }
        }
    }
}
