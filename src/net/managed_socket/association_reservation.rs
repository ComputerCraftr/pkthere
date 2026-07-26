use super::{
    AssociationOperation, AssociationState, ClearTransitionPhase, DisconnectOutcome, ManagedSocket,
    ManagedSocketError, PeerVerification, PublishedAssociationMode, RetiredTopologyReservation,
    TopologyBatchStep, TopologyReservation, peer_network_address_matches,
};
use socket2::{SockAddr, Socket};
use std::io;
use std::net::SocketAddr;

impl TopologyReservation {
    /// Releases dynamic co-hold tracking while retaining the closed topology
    /// gate and this reservation's exclusive typestate ownership.
    ///
    /// Group transactions park reservations in reverse acquisition order
    /// before applying socket operations. Final publication remains consuming,
    /// and no other reservation can enter while the gate is closed.
    pub(in crate::net) fn park_authority(
        &mut self,
        _step: &TopologyBatchStep<'_>,
    ) -> Result<(), ManagedSocketError> {
        if self.completed || self._authority.is_none() {
            return Err(ManagedSocketError::TopologyReservationLost {
                operation: self.operation,
            });
        }
        drop(self._authority.take());
        Ok(())
    }

    fn retire_descriptor_owner(&mut self) -> Result<(), ManagedSocketError> {
        self.socket.prepare_descriptor_retirement()?;
        drop(self._authority.take());
        if self.socket.retire_descriptor_after_revocation()? {
            Ok(())
        } else {
            Err(ManagedSocketError::DescriptorOwnershipLost {
                stage: "required owner retirement",
            })
        }
    }

    #[inline]
    pub(crate) const fn previous_epoch(&self) -> u64 {
        self.previous.epoch()
    }

    pub(crate) fn connect_unconnected(
        &mut self,
        peer: SocketAddr,
    ) -> Result<(), ManagedSocketError> {
        if !matches!(self.previous, AssociationState::Unconnected { .. }) || self.staged.is_some() {
            return Err(ManagedSocketError::InvalidTransition {
                operation: AssociationOperation::Connect,
                current: self.staged.unwrap_or(self.previous),
            });
        }
        let descriptor = self
            .socket
            .transition_descriptor(AssociationOperation::Connect)?;
        let transition = self
            .socket
            .backend_connect(&descriptor, &SockAddr::from(peer))
            .and_then(|()| self.socket.verify_connected_peer(&descriptor, peer))
            .and_then(|()| self.socket.backend_local_addr(&descriptor));
        let local_bind = match transition {
            Ok(local_bind) => local_bind,
            Err(source) => {
                self.staged = Some(AssociationState::Poisoned {
                    operation: AssociationOperation::Connect,
                    previous_peer: None,
                    epoch: self.epoch,
                });
                return Err(ManagedSocketError::Syscall {
                    operation: AssociationOperation::Connect,
                    source,
                });
            }
        };
        self.staged = Some(AssociationState::Connected {
            peer,
            epoch: self.epoch,
        });
        self.staged_local_bind = Some(local_bind);
        Ok(())
    }

    pub(crate) fn disconnect_connected(&mut self) -> Result<(), ManagedSocketError> {
        let AssociationState::Connected {
            peer: previous_peer,
            ..
        } = self.previous
        else {
            return Err(ManagedSocketError::InvalidTransition {
                operation: AssociationOperation::Disconnect,
                current: self.staged.unwrap_or(self.previous),
            });
        };
        if self.staged.is_some() {
            return Err(ManagedSocketError::InvalidTransition {
                operation: AssociationOperation::Disconnect,
                current: self.staged.unwrap_or(self.previous),
            });
        }
        let descriptor = self
            .socket
            .transition_descriptor(AssociationOperation::Disconnect)?;
        match self.observe_disconnect(&descriptor, previous_peer) {
            DisconnectOutcome::ExactDisconnected => {
                self.phase = ClearTransitionPhase::DisconnectVerified;
                self.staged = Some(AssociationState::Unconnected { epoch: self.epoch });
                Ok(())
            }
            DisconnectOutcome::UnchangedConnected {
                local_after,
                peer_after,
                syscall_error,
            } => {
                self.phase = ClearTransitionPhase::GateClosed;
                self.rollback_inner()?;
                Err(ManagedSocketError::DisconnectUnchanged {
                    local: local_after,
                    peer: peer_after,
                    syscall_error: syscall_error.map(|error| error.to_string()),
                })
            }
            DisconnectOutcome::ChangedUnexpectedly {
                local_after,
                peer_after,
                syscall_error,
            } => {
                drop(descriptor);
                self.retire_after_irreversible_disconnect()?;
                Err(ManagedSocketError::DisconnectChangedUnexpectedly {
                    local: local_after,
                    peer: peer_after,
                    syscall_error: syscall_error.map(|error| error.to_string()),
                })
            }
            DisconnectOutcome::Indeterminate {
                source,
                syscall_error,
            } => {
                drop(descriptor);
                self.retire_after_irreversible_disconnect()?;
                Err(ManagedSocketError::DisconnectIndeterminate {
                    cause: source.to_string(),
                    syscall_error: syscall_error.map(|error| error.to_string()),
                })
            }
        }
    }

    pub(crate) fn reconnect_connected(
        &mut self,
        new_peer: SocketAddr,
    ) -> Result<(), ManagedSocketError> {
        let AssociationState::Connected {
            peer: previous_peer,
            ..
        } = self.previous
        else {
            return Err(ManagedSocketError::InvalidTransition {
                operation: AssociationOperation::Reconnect,
                current: self.staged.unwrap_or(self.previous),
            });
        };
        if self.staged.is_some() {
            return Err(ManagedSocketError::InvalidTransition {
                operation: AssociationOperation::Reconnect,
                current: self.staged.unwrap_or(self.previous),
            });
        }
        let descriptor = self
            .socket
            .transition_descriptor(AssociationOperation::Reconnect)?;
        match self.observe_disconnect(&descriptor, previous_peer) {
            DisconnectOutcome::ExactDisconnected => {
                self.phase = ClearTransitionPhase::DisconnectVerified;
            }
            DisconnectOutcome::UnchangedConnected {
                local_after,
                peer_after,
                syscall_error,
            } => {
                self.phase = ClearTransitionPhase::GateClosed;
                self.rollback_inner()?;
                return Err(ManagedSocketError::DisconnectUnchanged {
                    local: local_after,
                    peer: peer_after,
                    syscall_error: syscall_error.map(|error| error.to_string()),
                });
            }
            DisconnectOutcome::ChangedUnexpectedly {
                local_after,
                peer_after,
                syscall_error,
            } => {
                drop(descriptor);
                self.retire_after_irreversible_disconnect()?;
                return Err(ManagedSocketError::DisconnectChangedUnexpectedly {
                    local: local_after,
                    peer: peer_after,
                    syscall_error: syscall_error.map(|error| error.to_string()),
                });
            }
            DisconnectOutcome::Indeterminate {
                source,
                syscall_error,
            } => {
                drop(descriptor);
                self.retire_after_irreversible_disconnect()?;
                return Err(ManagedSocketError::DisconnectIndeterminate {
                    cause: source.to_string(),
                    syscall_error: syscall_error.map(|error| error.to_string()),
                });
            }
        }
        let transition = self
            .socket
            .backend_connect(&descriptor, &SockAddr::from(new_peer))
            .and_then(|()| self.socket.verify_connected_peer(&descriptor, new_peer))
            .and_then(|()| {
                let local = self.socket.backend_local_addr(&descriptor)?;
                if local == self.previous_local_bind {
                    Ok(())
                } else {
                    Err(io::Error::other(format!(
                        "reconnect changed required local bind from {} to {local}",
                        self.previous_local_bind
                    )))
                }
            });
        match transition {
            Ok(()) => {
                self.staged = Some(AssociationState::Connected {
                    peer: new_peer,
                    epoch: self.epoch,
                });
                Ok(())
            }
            Err(source) => {
                drop(descriptor);
                self.retire_after_irreversible_disconnect()?;
                Err(ManagedSocketError::Syscall {
                    operation: AssociationOperation::Reconnect,
                    source,
                })
            }
        }
    }

    pub(in crate::net::managed_socket) fn observe_disconnect(
        &mut self,
        descriptor: &Socket,
        previous_peer: SocketAddr,
    ) -> DisconnectOutcome {
        let local_before = match self.socket.backend_local_addr(descriptor) {
            Ok(local) => local,
            Err(source) => {
                self.phase = ClearTransitionPhase::Poisoned;
                return DisconnectOutcome::Indeterminate {
                    source,
                    syscall_error: None,
                };
            }
        };
        let syscall_error = {
            let _operation = ManagedSocket::socket_operation_scope(
                crate::authority::OperationId::SocketDisconnect,
            );
            self.socket.inner.backend.disconnect(descriptor).err()
        };
        self.phase = ClearTransitionPhase::DisconnectAttempted;
        let local_after = match self.socket.backend_local_addr(descriptor) {
            Ok(local) => local,
            Err(source) => {
                return DisconnectOutcome::Indeterminate {
                    source,
                    syscall_error,
                };
            }
        };
        let peer_after = match self.socket.backend_peer_addr(descriptor) {
            Ok(peer) => peer,
            Err(source) => {
                return DisconnectOutcome::Indeterminate {
                    source,
                    syscall_error,
                };
            }
        };
        match peer_after {
            None if local_after == self.previous_local_bind
                && !matches!(
                    self.socket.inner.peer_verification,
                    PeerVerification::ConnectSuccess
                ) =>
            {
                DisconnectOutcome::ExactDisconnected
            }
            None if local_after == self.previous_local_bind
                && matches!(
                    self.socket.inner.peer_verification,
                    PeerVerification::ConnectSuccess
                ) =>
            {
                DisconnectOutcome::Indeterminate {
                    source: io::Error::new(
                        io::ErrorKind::Unsupported,
                        "disconnect peer inspection is unavailable for this socket path",
                    ),
                    syscall_error,
                }
            }
            Some(peer)
                if local_after == local_before
                    && match self.socket.inner.peer_verification {
                        PeerVerification::RequirePeerAddr => peer == previous_peer,
                        PeerVerification::RequirePeerNetworkAddress => {
                            peer_network_address_matches(previous_peer, peer)
                        }
                        PeerVerification::ConnectSuccess => false,
                    } =>
            {
                DisconnectOutcome::UnchangedConnected {
                    local_after,
                    peer_after: peer,
                    syscall_error,
                }
            }
            peer_after => DisconnectOutcome::ChangedUnexpectedly {
                local_after,
                peer_after,
                syscall_error,
            },
        }
    }

    pub(in crate::net::managed_socket) fn observe_rollback_disconnect(
        &mut self,
        descriptor: &Socket,
        staged_peer: SocketAddr,
    ) -> Result<(), ManagedSocketError> {
        match self.observe_disconnect(descriptor, staged_peer) {
            DisconnectOutcome::ExactDisconnected => {
                self.phase = ClearTransitionPhase::GateClosed;
                Ok(())
            }
            DisconnectOutcome::UnchangedConnected {
                local_after,
                peer_after,
                syscall_error,
            } => Err(ManagedSocketError::DisconnectUnchanged {
                local: local_after,
                peer: peer_after,
                syscall_error: syscall_error.map(|error| error.to_string()),
            }),
            DisconnectOutcome::ChangedUnexpectedly {
                local_after,
                peer_after,
                syscall_error,
            } => Err(ManagedSocketError::DisconnectChangedUnexpectedly {
                local: local_after,
                peer: peer_after,
                syscall_error: syscall_error.map(|error| error.to_string()),
            }),
            DisconnectOutcome::Indeterminate {
                source,
                syscall_error,
            } => Err(ManagedSocketError::DisconnectIndeterminate {
                cause: source.to_string(),
                syscall_error: syscall_error.map(|error| error.to_string()),
            }),
        }
    }

    pub(in crate::net::managed_socket) fn verify_required_local_bind(
        &self,
        descriptor: &Socket,
    ) -> Result<(), ManagedSocketError> {
        let local = self
            .socket
            .backend_local_addr(descriptor)
            .map_err(|source| ManagedSocketError::DisconnectIndeterminate {
                cause: source.to_string(),
                syscall_error: None,
            })?;
        if local == self.previous_local_bind {
            Ok(())
        } else {
            let peer = self
                .socket
                .backend_peer_addr(descriptor)
                .map_err(|source| ManagedSocketError::DisconnectIndeterminate {
                    cause: source.to_string(),
                    syscall_error: None,
                })?;
            Err(ManagedSocketError::DisconnectChangedUnexpectedly {
                local,
                peer,
                syscall_error: None,
            })
        }
    }

    pub(in crate::net::managed_socket) fn retire_after_irreversible_disconnect(
        &mut self,
    ) -> Result<(), ManagedSocketError> {
        self.phase = ClearTransitionPhase::Poisoned;
        self.retire_descriptor_owner()?;
        self.phase = ClearTransitionPhase::DescriptorRetired;
        self.staged = Some(AssociationState::Retired { epoch: self.epoch });
        Ok(())
    }

    fn retire_descriptor_for_replacement(&mut self) -> Result<(), ManagedSocketError> {
        if self.completed
            || !matches!(
                self.phase,
                ClearTransitionPhase::GateClosed
                    | ClearTransitionPhase::DisconnectVerified
                    | ClearTransitionPhase::Poisoned
            )
        {
            return Err(ManagedSocketError::TopologyReservationLost {
                operation: self.operation,
            });
        }
        if let Err(error) = self.retire_descriptor_owner() {
            self.phase = ClearTransitionPhase::Poisoned;
            return Err(error);
        }
        self.phase = ClearTransitionPhase::DescriptorRetired;
        self.staged = Some(AssociationState::Retired { epoch: self.epoch });
        Ok(())
    }

    pub(crate) fn into_retired_for_replacement(
        self,
    ) -> Result<RetiredTopologyReservation, ManagedSocketError> {
        super::retirement_core::retire_socket(self)
    }

    pub(super) fn mark_replacement_bound(&mut self) -> Result<(), ManagedSocketError> {
        if self.completed || self.phase != ClearTransitionPhase::DescriptorRetired {
            return Err(ManagedSocketError::TopologyReservationLost {
                operation: self.operation,
            });
        }
        self.phase = ClearTransitionPhase::ReplacementBound;
        Ok(())
    }

    const fn crossed_irreversible_point(&self) -> bool {
        matches!(
            self.phase,
            ClearTransitionPhase::DisconnectAttempted
                | ClearTransitionPhase::DisconnectVerified
                | ClearTransitionPhase::DescriptorRetired
                | ClearTransitionPhase::ReplacementBound
                | ClearTransitionPhase::Poisoned
        )
    }

    pub(crate) fn transition_local_addr(&self) -> Result<SocketAddr, ManagedSocketError> {
        let descriptor = self.socket.transition_descriptor(self.operation)?;
        self.socket
            .backend_local_addr(&descriptor)
            .map_err(|source| ManagedSocketError::Syscall {
                operation: self.operation,
                source,
            })
    }

    pub(crate) fn commit(mut self) -> Result<(), ManagedSocketError> {
        if let AssociationState::Retired { epoch } = self.previous {
            return Err(ManagedSocketError::Retired {
                operation: self.operation,
                epoch,
            });
        }
        let committed = self.staged.unwrap_or(match self.previous {
            AssociationState::Unconnected { .. } => {
                AssociationState::Unconnected { epoch: self.epoch }
            }
            AssociationState::Connected { peer, .. } => AssociationState::Connected {
                peer,
                epoch: self.epoch,
            },
            AssociationState::Poisoned {
                operation,
                previous_peer,
                ..
            } => AssociationState::Poisoned {
                operation,
                previous_peer,
                epoch: self.epoch,
            },
            AssociationState::Retired { .. } => self.previous,
        });
        self.finish(committed)?;
        self.phase = ClearTransitionPhase::Published;
        Ok(())
    }

    pub(crate) fn commit_publication(mut self) -> Result<(), ManagedSocketError> {
        if let AssociationState::Retired { epoch } = self.previous {
            return Err(ManagedSocketError::Retired {
                operation: self.operation,
                epoch,
            });
        }
        let committed = self.staged.unwrap_or(match self.previous {
            AssociationState::Unconnected { .. } => {
                AssociationState::Unconnected { epoch: self.epoch }
            }
            AssociationState::Connected { peer, .. } => AssociationState::Connected {
                peer,
                epoch: self.epoch,
            },
            AssociationState::Poisoned {
                operation,
                previous_peer,
                ..
            } => AssociationState::Poisoned {
                operation,
                previous_peer,
                epoch: self.epoch,
            },
            AssociationState::Retired { .. } => self.previous,
        });
        self.finish(committed)?;
        self.socket.mark_authority_identity_published();
        self.phase = ClearTransitionPhase::Published;
        Ok(())
    }

    pub(in crate::net::managed_socket) fn publish_retired(
        mut self,
    ) -> Result<(), ManagedSocketError> {
        if !matches!(
            self.phase,
            ClearTransitionPhase::DescriptorRetired | ClearTransitionPhase::ReplacementBound
        ) {
            return Err(ManagedSocketError::TopologyReservationLost {
                operation: self.operation,
            });
        }
        self.finish(AssociationState::Retired { epoch: self.epoch })?;
        self.phase = ClearTransitionPhase::Published;
        Ok(())
    }

    /// Consumes a failed transition and chooses its only legal terminal
    /// disposition from the owned phase. Callers cannot inspect a Boolean and
    /// then invoke rollback or retirement independently.
    pub(crate) fn finish_failed_transition(mut self) -> Result<(), ManagedSocketError> {
        if !self.crossed_irreversible_point() {
            return self.rollback();
        }
        if !matches!(
            self.phase,
            ClearTransitionPhase::DescriptorRetired | ClearTransitionPhase::ReplacementBound
        ) {
            self.phase = ClearTransitionPhase::Poisoned;
            self.retire_descriptor_owner()?;
            self.phase = ClearTransitionPhase::DescriptorRetired;
            self.staged = Some(AssociationState::Retired { epoch: self.epoch });
        }
        super::retirement_core::retire_socket(self)?.commit()
    }

    pub(crate) fn rollback(mut self) -> Result<(), ManagedSocketError> {
        self.rollback_inner()
    }

    pub(in crate::net::managed_socket) fn rollback_inner(
        &mut self,
    ) -> Result<(), ManagedSocketError> {
        if self.completed {
            return Ok(());
        }
        self.staged_local_bind = None;
        if matches!(
            self.phase,
            ClearTransitionPhase::DisconnectAttempted
                | ClearTransitionPhase::DisconnectVerified
                | ClearTransitionPhase::Poisoned
        ) {
            self.retire_descriptor_owner()?;
            self.phase = ClearTransitionPhase::DescriptorRetired;
            self.finish_inner(AssociationState::Retired { epoch: self.epoch })?;
            return Err(ManagedSocketError::TopologyReservationLost {
                operation: self.operation,
            });
        }
        if matches!(
            self.phase,
            ClearTransitionPhase::DescriptorRetired | ClearTransitionPhase::ReplacementBound
        ) {
            self.phase = ClearTransitionPhase::DescriptorRetired;
            self.finish_inner(AssociationState::Retired { epoch: self.epoch })?;
            return Err(ManagedSocketError::TopologyReservationLost {
                operation: self.operation,
            });
        }
        if let Some(staged) = self.staged {
            if matches!(staged, AssociationState::Poisoned { .. }) {
                self.finish_inner(staged)?;
                return Err(ManagedSocketError::TopologyReservationLost {
                    operation: self.operation,
                });
            }
            let descriptor = self.socket.transition_descriptor(self.operation)?;
            let restored = match (self.previous, staged) {
                (
                    AssociationState::Unconnected { .. },
                    AssociationState::Connected {
                        peer: staged_peer, ..
                    },
                ) => self.observe_rollback_disconnect(&descriptor, staged_peer),
                (
                    AssociationState::Connected { peer, .. },
                    AssociationState::Unconnected { .. },
                ) => self
                    .socket
                    .backend_connect(&descriptor, &SockAddr::from(peer))
                    .and_then(|()| self.socket.verify_connected_peer(&descriptor, peer))
                    .map_err(|source| ManagedSocketError::Syscall {
                        operation: self.operation,
                        source,
                    })
                    .and_then(|()| self.verify_required_local_bind(&descriptor)),
                (
                    AssociationState::Connected {
                        peer: previous_peer,
                        ..
                    },
                    AssociationState::Connected {
                        peer: staged_peer, ..
                    },
                ) if previous_peer != staged_peer => self
                    .observe_rollback_disconnect(&descriptor, staged_peer)
                    .and_then(|()| {
                        self.socket
                            .backend_connect(&descriptor, &SockAddr::from(previous_peer))
                            .map_err(|source| ManagedSocketError::Syscall {
                                operation: self.operation,
                                source,
                            })
                    })
                    .and_then(|()| {
                        self.socket
                            .verify_connected_peer(&descriptor, previous_peer)
                            .map_err(|source| ManagedSocketError::Syscall {
                                operation: self.operation,
                                source,
                            })
                    })
                    .and_then(|()| self.verify_required_local_bind(&descriptor)),
                _ => Ok(()),
            };
            if let Err(source) = restored {
                drop(descriptor);
                self.retire_after_irreversible_disconnect()?;
                self.finish_inner(AssociationState::Retired { epoch: self.epoch })?;
                return Err(source);
            }
        }
        let restored = match self.previous {
            AssociationState::Unconnected { .. } => {
                AssociationState::Unconnected { epoch: self.epoch }
            }
            AssociationState::Connected { peer, .. } => AssociationState::Connected {
                peer,
                epoch: self.epoch,
            },
            AssociationState::Poisoned {
                operation,
                previous_peer,
                ..
            } => AssociationState::Poisoned {
                operation,
                previous_peer,
                epoch: self.epoch,
            },
            AssociationState::Retired { .. } => {
                return Err(ManagedSocketError::TopologyReservationLost {
                    operation: self.operation,
                });
            }
        };
        self.finish_inner(restored)
    }

    pub(in crate::net::managed_socket) fn finish(
        &mut self,
        association: AssociationState,
    ) -> Result<(), ManagedSocketError> {
        self.finish_inner(association)
    }

    pub(in crate::net::managed_socket) fn finish_inner(
        &mut self,
        association: AssociationState,
    ) -> Result<(), ManagedSocketError> {
        let mut state = self.socket.lock_association_state();
        if state.association != self.previous {
            let previous_peer = match state.association {
                AssociationState::Connected { peer, .. } => Some(peer),
                AssociationState::Poisoned { previous_peer, .. } => previous_peer,
                AssociationState::Unconnected { .. } | AssociationState::Retired { .. } => None,
            };
            state.association = AssociationState::Poisoned {
                operation: self.operation,
                previous_peer,
                epoch: self.epoch,
            };
            self.socket
                .publish_stable_association(PublishedAssociationMode::Poisoned, self.epoch)?;
            self.completed = true;
            return Err(ManagedSocketError::TopologyReservationLost {
                operation: self.operation,
            });
        }
        let resulting_local_bind = self.staged_local_bind.unwrap_or(state.required_local_bind);
        state.publish(association, resulting_local_bind);
        let mode = match association {
            AssociationState::Unconnected { .. } => PublishedAssociationMode::Unconnected,
            AssociationState::Connected { .. } => PublishedAssociationMode::Connected,
            AssociationState::Poisoned { .. } => PublishedAssociationMode::Poisoned,
            AssociationState::Retired { .. } => PublishedAssociationMode::Retired,
        };
        self.socket.publish_stable_association(mode, self.epoch)?;
        self.completed = true;
        Ok(())
    }
}

impl super::retirement_core::SocketRetirementOwner for TopologyReservation {
    type Error = ManagedSocketError;

    fn retire_descriptor(&mut self) -> Result<(), Self::Error> {
        if self.phase == ClearTransitionPhase::DescriptorRetired {
            return Ok(());
        }
        self.retire_descriptor_for_replacement()
    }

    fn bind_replacement(&mut self) -> Result<(), Self::Error> {
        self.mark_replacement_bound()
    }

    fn publish_retirement(self) -> Result<(), Self::Error> {
        self.publish_retired()
    }
}
