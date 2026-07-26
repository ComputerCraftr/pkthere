use super::{
    ClientFlowKey, ClientFlowReservation, ClientFlowTopologyReservation, DroppedReplyIdHandshake,
    FlowAuthorityError, FlowRuntimeState, FlowTopologyError, FlowTopologyWriteReservation,
};
use std::time::Instant;

pub(crate) struct ClientFlowSocketTransitionsApplied<'reservation, 'state> {
    pub(super) owner: &'reservation mut ClientFlowReservation<'state>,
    pub(super) topology: super::topology::SocketTransitionsAppliedTopology<'state>,
}

pub(crate) struct PreparedClientFlowTopology<'reservation, 'state> {
    pub(super) owner: &'reservation mut ClientFlowReservation<'state>,
    pub(super) topology: super::topology::PreparedTopology<'state>,
}

pub(crate) struct CommittedClientFlowTopology<'reservation, 'state> {
    pub(super) owner: &'reservation mut ClientFlowReservation<'state>,
    pub(super) topology: super::topology::SessionCommittedTopology<'state>,
}

enum FlowVisibilityAction<'state> {
    PublishCommitted(super::topology::SessionCommittedTopology<'state>),
    PublishManager(super::topology::PreparedTopology<'state>),
    Cancel(FlowTopologyWriteReservation<'state>),
}

struct RuntimeFlowSnapshotPublication<'state> {
    state: &'state FlowRuntimeState,
    publication_epoch: u64,
    action: Option<FlowVisibilityAction<'state>>,
}

impl crate::atomic_core::FlowSnapshotPublicationBackend for RuntimeFlowSnapshotPublication<'_> {
    type Error = FlowTopologyError;

    fn install_snapshot(&mut self) -> Result<(), Self::Error> {
        self.state
            .publish_admission_snapshot(self.publication_epoch);
        Ok(())
    }

    fn publish_visibility(&mut self) -> Result<(), Self::Error> {
        let action = self.action.take().ok_or(FlowTopologyError::OwnershipLost)?;
        match action {
            FlowVisibilityAction::PublishCommitted(topology) => topology.publish(),
            FlowVisibilityAction::PublishManager(topology) => topology.publish_manager_only(),
            FlowVisibilityAction::Cancel(topology) => topology.cancel(),
        }
    }
}

fn finish_flow_snapshot_publication<'state>(
    state: &'state FlowRuntimeState,
    publication_epoch: u64,
    action: FlowVisibilityAction<'state>,
) -> Result<(), FlowTopologyError> {
    let publication = RuntimeFlowSnapshotPublication {
        state,
        publication_epoch,
        action: Some(action),
    };
    crate::atomic_core::FlowSnapshotPublicationCore::new(publication)
        .install_snapshot()?
        .publish_visibility()
}

impl<'state> ClientFlowReservation<'state> {
    fn validate(&self) -> Result<(), crate::net::sock_mgr::transaction_lock::ReservationError> {
        self.reservation
            .as_ref()
            .ok_or(crate::net::sock_mgr::transaction_lock::ReservationError::OwnershipLost)?
            .validate()
            .inspect_err(|_| {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client-flow reservation lost ownership"
                ));
            })
    }

    #[inline]
    pub(crate) fn assert_current(
        &self,
    ) -> Result<(), crate::net::sock_mgr::transaction_lock::ReservationError> {
        self.validate()
    }

    #[inline]
    pub(crate) fn is_locked(
        &self,
    ) -> Result<bool, crate::net::sock_mgr::transaction_lock::ReservationError> {
        self.validate()?;
        Ok(self.state.is_locked() || self.state.reset_send_in_flight())
    }

    #[inline]
    pub(crate) fn publish_locked_with_claim(
        &self,
        flow: ClientFlowKey,
        flow_claim_generation: Option<std::num::NonZeroU64>,
    ) -> Result<(), FlowAuthorityError> {
        self.validate().map_err(FlowAuthorityError::from)?;
        self.state.publish_locked(self, flow, flow_claim_generation)
    }

    #[cfg(test)]
    pub(crate) fn publish_locked(&self, flow: ClientFlowKey) -> Result<(), FlowAuthorityError> {
        self.publish_locked_with_claim(flow, None)
    }

    #[inline]
    pub(crate) fn reset(&self) -> Result<Option<DroppedReplyIdHandshake>, FlowAuthorityError> {
        self.validate().map_err(FlowAuthorityError::from)?;
        self.state.reset_under(self)
    }

    pub(crate) fn flow_claim_binding(
        &self,
    ) -> Result<(Option<ClientFlowKey>, Option<std::num::NonZeroU64>), FlowAuthorityError> {
        self.validate().map_err(FlowAuthorityError::from)?;
        self.state.flow_claim_binding_under(self)
    }

    pub(crate) fn publication_epoch(&self) -> Result<u64, FlowAuthorityError> {
        self.validate().map_err(|error| {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client-flow reservation lost ownership before snapshot publication"
                ));
            }
            FlowAuthorityError::Reservation(error)
        })?;
        Ok(self.publication_epoch)
    }

    pub(crate) fn state_flow_epoch(&self) -> Result<u64, FlowAuthorityError> {
        self.validate().map_err(FlowAuthorityError::from)?;
        self.publication_epoch()
    }

    pub(crate) fn reserve_topology_until(
        &mut self,
        _deadline: Instant,
    ) -> Result<ClientFlowTopologyReservation<'_, 'state>, FlowTopologyError> {
        self.validate().map_err(|error| {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client-flow reservation lost ownership before topology reservation"
                ));
            }
            FlowTopologyError::OwnershipLost
        })?;
        self.state
            .publish_admission_snapshot(self.publication_epoch);
        let topology = self.topology.take().ok_or_else(|| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "client-flow topology reservation was consumed more than once"
            ));
            FlowTopologyError::OwnershipLost
        })?;
        Ok(ClientFlowTopologyReservation {
            owner: self,
            topology,
        })
    }

    /// Completes both one-shot reservation authorities exactly once.
    pub(crate) fn commit(mut self) -> Result<(), FlowAuthorityError> {
        self.finish(true)
    }

    pub(crate) fn rollback(mut self) -> Result<(), FlowAuthorityError> {
        self.finish(false)
    }

    fn finish(&mut self, committed: bool) -> Result<(), FlowAuthorityError> {
        self.validate().map_err(FlowAuthorityError::from)?;
        if let Some(topology) = self.topology.take() {
            finish_flow_snapshot_publication(
                self.state,
                self.publication_epoch,
                FlowVisibilityAction::Cancel(topology),
            )?;
        }
        let reservation = self.reservation.take().ok_or_else(|| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "client-flow FIFO reservation was consumed more than once"
            ));
            FlowAuthorityError::Reservation(
                crate::net::sock_mgr::transaction_lock::ReservationError::OwnershipLost,
            )
        })?;
        if committed {
            reservation.commit().map(|_| ()).map_err(Into::into)
        } else {
            reservation.rollback().map_err(Into::into)
        }
    }
}

impl<'reservation, 'state> ClientFlowTopologyReservation<'reservation, 'state> {
    fn validate_owner(&self) -> Result<(), FlowTopologyError> {
        self.owner.validate().map_err(|error| {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client-flow reservation lost ownership during topology transaction"
                ));
            }
            FlowTopologyError::OwnershipLost
        })
    }

    pub(crate) fn socket_transitions_applied(
        self,
    ) -> Result<ClientFlowSocketTransitionsApplied<'reservation, 'state>, FlowTopologyError> {
        self.validate_owner()?;
        Ok(ClientFlowSocketTransitionsApplied {
            owner: self.owner,
            topology: self.topology.socket_transitions_applied()?,
        })
    }
}

impl<'reservation, 'state> ClientFlowSocketTransitionsApplied<'reservation, 'state> {
    pub(crate) fn manager_state_prepared(
        self,
    ) -> Result<PreparedClientFlowTopology<'reservation, 'state>, FlowTopologyError> {
        self.owner
            .validate()
            .map_err(|_| FlowTopologyError::OwnershipLost)?;
        Ok(PreparedClientFlowTopology {
            owner: self.owner,
            topology: self.topology.manager_state_prepared()?,
        })
    }
}

impl<'reservation, 'state> PreparedClientFlowTopology<'reservation, 'state> {
    pub(crate) fn commit_session_with<T>(
        self,
        mutation: impl FnOnce(&ClientFlowReservation<'state>) -> Result<T, FlowAuthorityError>,
    ) -> Result<(CommittedClientFlowTopology<'reservation, 'state>, T), FlowAuthorityError> {
        self.owner.validate().map_err(FlowAuthorityError::from)?;
        let result = mutation(self.owner)?;
        let resulting_epoch = self.owner.state_flow_epoch()?;
        let topology = self
            .topology
            .commit_session(self.owner.expected_epoch, resulting_epoch)?;
        Ok((
            CommittedClientFlowTopology {
                owner: self.owner,
                topology,
            },
            result,
        ))
    }

    pub(crate) fn publish_manager_only(self) -> Result<(), FlowTopologyError> {
        self.owner
            .validate()
            .map_err(|_| FlowTopologyError::OwnershipLost)?;
        finish_flow_snapshot_publication(
            self.owner.state,
            self.owner.publication_epoch,
            FlowVisibilityAction::PublishManager(self.topology),
        )
    }
}

impl CommittedClientFlowTopology<'_, '_> {
    pub(crate) fn publish(self) -> Result<(), FlowTopologyError> {
        self.owner
            .validate()
            .map_err(|_| FlowTopologyError::OwnershipLost)?;
        finish_flow_snapshot_publication(
            self.owner.state,
            self.owner.publication_epoch,
            FlowVisibilityAction::PublishCommitted(self.topology),
        )
    }
}

impl Drop for ClientFlowReservation<'_> {
    fn drop(&mut self) {
        if let Some(topology) = self.topology.take()
            && finish_flow_snapshot_publication(
                self.state,
                self.publication_epoch,
                FlowVisibilityAction::Cancel(topology),
            )
            .is_err()
        {
            crate::runtime_support::publish_process_fatal(format_args!(
                "client-flow topology rollback lost snapshot publication authority"
            ));
        }
        // The FIFO guard retains its own emergency release path. Explicit
        // completion takes it first, preventing a second release.
    }
}
