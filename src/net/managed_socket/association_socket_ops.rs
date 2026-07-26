use super::{
    ActiveIoGuard, AssociationOperation, AssociationState, ClearTransitionPhase,
    DATA_PLANE_POLL_FALLBACK, IO_GATE_CLOSED, IoKind, IoLeaseAcquireError, LeaseDescriptor,
    ManagedSocket, ManagedSocketError, PeerVerification, PublishedAssociation,
    PublishedAssociationMode, SocketIoLane, TOPOLOGY_IO_DRAIN_TIMEOUT, TopologyAuthorityLease,
    TopologyReservation, WorkerDescriptorCache, next_association_epoch, release_socket_io_epoch,
};
use socket2::Socket;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

impl ManagedSocket {
    #[cfg(all(test, not(miri)))]
    pub(crate) fn connect_unconnected(&self, peer: SocketAddr) -> Result<(), ManagedSocketError> {
        let mut reservation = self.reserve_topology_waiting(AssociationOperation::Connect)?;
        reservation.connect_unconnected(peer)?;
        reservation.commit()
    }

    #[inline]
    pub(in crate::net::managed_socket) fn load_published_association(
        &self,
    ) -> PublishedAssociation {
        PublishedAssociation(self.inner.published_association.load(Ordering::Acquire))
    }

    pub(in crate::net::managed_socket) fn lock_association_state(
        &self,
    ) -> crate::authority::AuthorityMutexGuard<
        '_,
        crate::authority::tags::SocketAssociation,
        super::AssociationAuthorityState,
    > {
        crate::runtime_support::lock_authority_or_shutdown(
            &self.inner.association_state,
            "managed socket association",
        )
    }

    #[inline]
    pub(in crate::net::managed_socket) fn publish_stable_association(
        &self,
        mode: PublishedAssociationMode,
        epoch: u64,
    ) -> Result<(), ManagedSocketError> {
        let Some(published) = PublishedAssociation::new(mode, epoch) else {
            crate::runtime_support::publish_process_fatal(format_args!(
                "managed socket association epoch {epoch} cannot be published"
            ));
            return Err(ManagedSocketError::PublishedAssociationExhausted { epoch });
        };
        let _wait = self.inner.io_drain_wait.lock().map_err(|source| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "socket topology publication wait authority failed: {source}"
            ));
            ManagedSocketError::PublicationAuthorityLost { source }
        })?;
        let gate_state = if mode == PublishedAssociationMode::Retired {
            IO_GATE_CLOSED | epoch
        } else {
            epoch
        };
        crate::atomic_core::publish_socket_state_before_gate(
            &self.inner.published_association,
            published.0,
            &self.inner.io_gate,
            gate_state,
        );
        if mode != PublishedAssociationMode::Retired
            && self.inner.release_reserved_io_lanes().is_err()
        {
            crate::runtime_support::publish_process_fatal(format_args!(
                "socket topology writer lost an I/O-lane reservation while reopening"
            ));
            return Err(ManagedSocketError::TopologyReservationLost {
                operation: AssociationOperation::PublishMetadata,
            });
        }
        self.inner.io_drained.notify_all();
        Ok(())
    }

    pub(in crate::net::managed_socket) fn begin_transition(
        &self,
        state: crate::authority::AuthorityMutexGuard<
            '_,
            crate::authority::tags::SocketAssociation,
            super::AssociationAuthorityState,
        >,
        previous: AssociationState,
        epoch: u64,
        operation: AssociationOperation,
    ) -> Result<(), ManagedSocketError> {
        let (stable_mode, stable_epoch) = match previous {
            AssociationState::Unconnected { epoch } => {
                (PublishedAssociationMode::Unconnected, epoch)
            }
            AssociationState::Connected { epoch, .. } => {
                (PublishedAssociationMode::Connected, epoch)
            }
            AssociationState::Poisoned { epoch, .. } => (PublishedAssociationMode::Poisoned, epoch),
            AssociationState::Retired { epoch } => (PublishedAssociationMode::Retired, epoch),
        };
        let stable = PublishedAssociation::new(stable_mode, stable_epoch).ok_or(
            ManagedSocketError::PublishedAssociationExhausted {
                epoch: stable_epoch,
            },
        )?;
        let transitioning =
            PublishedAssociation::new(PublishedAssociationMode::Transitioning, epoch)
                .ok_or(ManagedSocketError::PublishedAssociationExhausted { epoch })?;
        if crate::atomic_core::close_expected_epoch_gate(
            &self.inner.io_gate,
            stable_epoch,
            IO_GATE_CLOSED,
        )
        .is_err()
        {
            return Err(ManagedSocketError::TopologyReservationLost { operation });
        }
        if self
            .inner
            .published_association
            .compare_exchange(
                stable.0,
                transitioning.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.inner.io_gate.store(stable_epoch, Ordering::Release);
            return Err(ManagedSocketError::TopologyReservationLost { operation });
        }
        drop(state);

        let mut wait = self.inner.io_drain_wait.lock().unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "socket I/O drain authority failed: {error}"
            ))
        });
        let deadline = Instant::now() + TOPOLOGY_IO_DRAIN_TIMEOUT;
        while !self.inner.reserve_idle_io_lanes() {
            if deadline.checked_duration_since(Instant::now()).is_none() {
                drop(wait);
                return Err(self.poison_after_io_drain_timeout(previous, operation, epoch));
            }
            let (next_wait, timed_out) = self
                .inner
                .io_drained
                .wait_until(wait, deadline)
                .unwrap_or_else(|error| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "socket I/O drain wait failed: {error}"
                    ))
                });
            wait = next_wait;
            if timed_out && !self.inner.reserve_idle_io_lanes() {
                drop(wait);
                return Err(self.poison_after_io_drain_timeout(previous, operation, epoch));
            }
        }
        drop(wait);
        Ok(())
    }

    pub(in crate::net::managed_socket) fn poison_after_io_drain_timeout(
        &self,
        previous: AssociationState,
        operation: AssociationOperation,
        epoch: u64,
    ) -> ManagedSocketError {
        let active_io = self.active_io_count();
        let mut state = self.lock_association_state();
        if state.association != previous {
            return ManagedSocketError::TopologyReservationLost { operation };
        }
        let previous_peer = match previous {
            AssociationState::Connected { peer, .. } => Some(peer),
            _ => None,
        };
        let required_local_bind = state.required_local_bind;
        state.publish(
            AssociationState::Poisoned {
                operation,
                previous_peer,
                epoch,
            },
            required_local_bind,
        );
        if let Err(error) =
            self.publish_stable_association(PublishedAssociationMode::Poisoned, epoch)
        {
            return error;
        }
        ManagedSocketError::TopologyQuiescenceLost {
            operation,
            active_io,
            epoch,
        }
    }

    pub(in crate::net::managed_socket) fn acquire_io_lease<'socket>(
        &'socket self,
        kind: IoKind,
        lane: SocketIoLane,
        worker_cache: Option<&'socket mut WorkerDescriptorCache>,
    ) -> io::Result<TopologyAuthorityLease<'socket>> {
        match (lane, worker_cache.as_ref()) {
            (SocketIoLane::Worker(_), Some(cache)) if cache.lane == lane => {}
            (SocketIoLane::Worker(_), Some(_)) => {
                return Err(io::Error::other(
                    "worker descriptor cache belongs to a different I/O lane",
                ));
            }
            (SocketIoLane::Worker(_), None) => {
                return Err(io::Error::other(
                    "worker socket I/O requires a worker-owned descriptor cache",
                ));
            }
            (SocketIoLane::Control, None) => {}
            (SocketIoLane::Control, Some(_)) => {
                return Err(io::Error::other(
                    "control socket I/O cannot borrow a worker descriptor cache",
                ));
            }
        }
        let Some(lane_slot) = self.inner.io_lane(lane) else {
            return Err(io::Error::other(ManagedSocketError::ActiveIoExhausted));
        };
        let epoch_result = match lane {
            SocketIoLane::Worker(_) => crate::atomic_core::acquire_epoch_lane(
                &self.inner.io_gate,
                &lane_slot.active_epoch,
                IO_GATE_CLOSED,
            ),
            SocketIoLane::Control => crate::atomic_core::acquire_contended_epoch_lane(
                &self.inner.io_gate,
                &lane_slot.active_epoch,
                IO_GATE_CLOSED,
            ),
        };
        let epoch = match epoch_result {
            Ok(epoch) => epoch,
            Err(crate::atomic_core::LaneAdmissionError::Closed) => {
                return Err(match self.load_published_association().mode() {
                    PublishedAssociationMode::Poisoned => {
                        self.poisoned_io_error("socket I/O rejected")
                    }
                    PublishedAssociationMode::Retired => {
                        io::Error::new(io::ErrorKind::BrokenPipe, "managed socket is retired")
                    }
                    PublishedAssociationMode::Transitioning
                    | PublishedAssociationMode::Connected
                    | PublishedAssociationMode::Unconnected => io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "managed socket topology is transitioning",
                    ),
                });
            }
            Err(
                crate::atomic_core::LaneAdmissionError::Occupied
                | crate::atomic_core::LaneAdmissionError::EpochExhausted,
            ) => {
                return Err(io::Error::other(ManagedSocketError::ActiveIoExhausted));
            }
        };
        let published = self.load_published_association();
        let association_error = match published.mode() {
            PublishedAssociationMode::Connected | PublishedAssociationMode::Unconnected
                if published.epoch() == epoch =>
            {
                None
            }
            PublishedAssociationMode::Transitioning => Some(IoLeaseAcquireError::Busy),
            PublishedAssociationMode::Poisoned => Some(IoLeaseAcquireError::Poisoned),
            PublishedAssociationMode::Retired => Some(IoLeaseAcquireError::Retired),
            PublishedAssociationMode::Connected | PublishedAssociationMode::Unconnected => {
                Some(IoLeaseAcquireError::Busy)
            }
        };
        if let Some(error) = association_error {
            if release_socket_io_epoch(lane, lane_slot, epoch).is_err() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "managed socket I/O lane ownership was lost after association revalidation"
                ));
            }
            return Err(match error {
                IoLeaseAcquireError::Busy => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "managed socket topology is transitioning",
                ),
                IoLeaseAcquireError::Poisoned => self.poisoned_io_error("socket I/O rejected"),
                IoLeaseAcquireError::Retired => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "managed socket is retired")
                }
            });
        }
        let descriptor = match worker_cache {
            Some(cache) => cache
                .descriptor(self, published.epoch())
                .map(LeaseDescriptor::Worker),
            None => self
                .transition_descriptor(AssociationOperation::PublishMetadata)
                .map(LeaseDescriptor::Control),
        };
        let descriptor = match descriptor {
            Ok(descriptor) => descriptor,
            Err(error) => {
                if release_socket_io_epoch(lane, lane_slot, epoch).is_err() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "managed socket I/O lane ownership was lost after descriptor retirement"
                    ));
                }
                crate::runtime_support::publish_process_fatal(format_args!(
                    "stable managed socket topology lost its persistent descriptor owner"
                ));
                return Err(io::Error::other(error));
            }
        };
        let lease = TopologyAuthorityLease {
            descriptor,
            published,
            _kind: kind,
            _authority: crate::authority::AuthorityScope::enter(self.authority_instance(
                crate::authority::AuthorityId::SocketIo,
                match kind {
                    IoKind::Receive => 0,
                    IoKind::Send => 1,
                },
                match lane {
                    SocketIoLane::Worker(index) => index as u64,
                    SocketIoLane::Control => u64::MAX,
                },
            ))
            .unwrap_or_else(|error| {
                if release_socket_io_epoch(lane, lane_slot, epoch).is_err() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "socket I/O lane ownership was lost after authority-order rejection"
                    ));
                }
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "socket I/O authority order was violated: {error}"
                ))
            }),
            _active_io: ActiveIoGuard {
                inner: self.inner.as_ref(),
                lane,
                epoch,
            },
        };
        Ok(lease)
    }

    pub(in crate::net::managed_socket) fn active_io_count(&self) -> usize {
        self.inner.active_io_count()
    }

    pub(crate) fn reserve_replacement(&self) -> Result<TopologyReservation, ManagedSocketError> {
        self.reserve_topology(AssociationOperation::Replace)
    }

    #[cfg(all(test, not(miri)))]
    pub(in crate::net::managed_socket) fn reserve_topology_waiting(
        &self,
        operation: AssociationOperation,
    ) -> Result<TopologyReservation, ManagedSocketError> {
        let deadline = Instant::now() + TOPOLOGY_IO_DRAIN_TIMEOUT;
        loop {
            match self.reserve_topology(operation) {
                Ok(reservation) => return Ok(reservation),
                Err(ManagedSocketError::TopologyReservationLost { .. }) => {
                    self.wait_for_topology_publication(deadline)
                        .map_err(|_| ManagedSocketError::TopologyReservationLost { operation })?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn reserve_topology(
        &self,
        operation: AssociationOperation,
    ) -> Result<TopologyReservation, ManagedSocketError> {
        let published = self.load_published_association();
        if published.mode() == PublishedAssociationMode::Retired {
            return Err(ManagedSocketError::Retired {
                operation,
                epoch: published.epoch(),
            });
        }
        if self.inner.io_gate.load(Ordering::Acquire) & IO_GATE_CLOSED != 0 {
            return Err(ManagedSocketError::TopologyReservationLost { operation });
        }
        let topology_authority = crate::authority::AuthorityScope::enter(self.authority_instance(
            crate::authority::AuthorityId::SocketTopology,
            0,
            self.topology_epoch(),
        ))
        .unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "socket topology authority order was violated: {error}"
            ))
        });
        let state = self.lock_association_state();
        let previous = state.association;
        match previous {
            AssociationState::Connected { .. }
                if matches!(operation, AssociationOperation::Connect) =>
            {
                return Err(ManagedSocketError::InvalidTransition {
                    operation,
                    current: previous,
                });
            }
            AssociationState::Unconnected { .. }
                if matches!(
                    operation,
                    AssociationOperation::Disconnect | AssociationOperation::Reconnect
                ) =>
            {
                return Err(ManagedSocketError::InvalidTransition {
                    operation,
                    current: previous,
                });
            }
            AssociationState::Poisoned {
                operation: poisoned_by,
                epoch,
                ..
            } if !matches!(
                operation,
                AssociationOperation::Replace | AssociationOperation::PublishMetadata
            ) =>
            {
                return Err(ManagedSocketError::Poisoned {
                    operation,
                    poisoned_by,
                    epoch,
                });
            }
            AssociationState::Retired { epoch } => {
                return Err(ManagedSocketError::Retired { operation, epoch });
            }
            _ => {}
        }
        if self.inner.io_gate.load(Ordering::Acquire) & IO_GATE_CLOSED != 0 {
            return Err(ManagedSocketError::TopologyReservationLost { operation });
        }
        let epoch = match previous {
            AssociationState::Unconnected { epoch }
            | AssociationState::Connected { epoch, .. }
            | AssociationState::Poisoned { epoch, .. } => {
                next_association_epoch(previous, operation, epoch)?
            }
            AssociationState::Retired { epoch } => {
                return Err(ManagedSocketError::Retired { operation, epoch });
            }
        };
        let previous_local_bind = state.required_local_bind;
        self.begin_transition(state, previous, epoch, operation)?;
        Ok(TopologyReservation {
            socket: self.clone(),
            previous,
            previous_local_bind,
            epoch,
            operation,
            staged: None,
            staged_local_bind: None,
            phase: ClearTransitionPhase::GateClosed,
            completed: false,
            _authority: Some(topology_authority),
        })
    }

    pub(crate) fn reconcile_destination_required(&self, expected_epoch: u64) -> io::Result<bool> {
        let deadline = Instant::now() + DATA_PLANE_POLL_FALLBACK;
        loop {
            let topology_authority =
                crate::authority::AuthorityScope::enter(self.authority_instance(
                    crate::authority::AuthorityId::SocketTopology,
                    0,
                    self.topology_epoch(),
                ))
                .unwrap_or_else(|error| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "socket topology authority order was violated: {error}"
                    ))
                });
            let state = self.lock_association_state();
            let previous = state.association;
            let next_epoch = match previous {
                AssociationState::Connected { epoch, .. } if epoch == expected_epoch => {
                    next_association_epoch(previous, AssociationOperation::Disconnect, epoch)
                        .map_err(io::Error::other)?
                }
                AssociationState::Unconnected { .. } => return Ok(false),
                AssociationState::Connected { .. } => {
                    return Err(io::Error::other(
                        "managed socket association changed during destination-required reconciliation",
                    ));
                }
                AssociationState::Poisoned {
                    operation, epoch, ..
                } => {
                    return Err(io::Error::other(format!(
                        "send reconciliation rejected: socket was poisoned by {operation:?} at epoch {epoch}"
                    )));
                }
                AssociationState::Retired { epoch } => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("send reconciliation rejected: socket retired at epoch {epoch}"),
                    ));
                }
            };
            let previous_local_bind = state.required_local_bind;
            match self.begin_transition(
                state,
                previous,
                next_epoch,
                AssociationOperation::Disconnect,
            ) {
                Ok(()) => {
                    let reservation = TopologyReservation {
                        socket: self.clone(),
                        previous,
                        previous_local_bind,
                        epoch: next_epoch,
                        operation: AssociationOperation::Disconnect,
                        staged: Some(AssociationState::Unconnected { epoch: next_epoch }),
                        staged_local_bind: None,
                        phase: ClearTransitionPhase::DisconnectVerified,
                        completed: false,
                        _authority: Some(topology_authority),
                    };
                    reservation.commit().map_err(io::Error::other)?;
                    return Ok(true);
                }
                Err(ManagedSocketError::TopologyReservationLost { .. }) => {
                    self.wait_for_topology_publication(deadline)?;
                }
                Err(error) => return Err(io::Error::other(error)),
            }
        }
    }

    pub(in crate::net::managed_socket) fn wait_for_topology_publication(
        &self,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut wait = self.inner.io_drain_wait.lock().unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "socket topology wait authority failed: {error}"
            ))
        });
        while self.load_published_association().mode() == PublishedAssociationMode::Transitioning {
            if deadline.checked_duration_since(Instant::now()).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "managed socket topology transition did not publish before send retry deadline",
                ));
            }
            let (next_wait, timed_out) = self
                .inner
                .io_drained
                .wait_until_as(
                    wait,
                    deadline,
                    crate::authority::WaitId::SocketTopologyPublication,
                )
                .unwrap_or_else(|error| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "socket topology wait failed: {error}"
                    ))
                });
            wait = next_wait;
            if timed_out
                && self.load_published_association().mode()
                    == PublishedAssociationMode::Transitioning
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "managed socket topology transition did not publish before send retry deadline",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::net::managed_socket) fn poisoned_io_error(&self, context: &str) -> io::Error {
        let state = self.lock_association_state().association;
        match state {
            AssociationState::Poisoned {
                operation, epoch, ..
            } => io::Error::other(format!(
                "{context}: socket was poisoned by {operation:?} at epoch {epoch}"
            )),
            AssociationState::Retired { epoch } => io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{context}: socket was retired at epoch {epoch}"),
            ),
            state => io::Error::other(format!(
                "{context}: published poison state disagrees with managed association {state:?}"
            )),
        }
    }

    pub(in crate::net::managed_socket) fn verify_connected_peer(
        &self,
        socket: &Socket,
        requested_peer: SocketAddr,
    ) -> io::Result<()> {
        if self.inner.peer_verification == PeerVerification::ConnectSuccess {
            return Ok(());
        }
        let observed_peer = self.backend_peer_addr(socket)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "connect succeeded without a kernel peer association",
            )
        })?;
        let peer_matches = self
            .inner
            .peer_verification
            .accepts_observation(Some(requested_peer), Some(observed_peer));
        if peer_matches {
            Ok(())
        } else {
            Err(io::Error::other(
                "kernel peer does not match the requested peer",
            ))
        }
    }
}
