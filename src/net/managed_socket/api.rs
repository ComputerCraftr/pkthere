use super::{
    AssociationOperation, AssociationState, DATA_PLANE_POLL_FALLBACK, DATA_PLANE_POLL_MINIMUM,
    DescriptorOwner, IoKind, ManagedReadiness, ManagedSendLease, ManagedSocket, ManagedSocketError,
    ManagedSocketInner, PeerVerification, PublishedAssociation, PublishedAssociationMode,
    SocketAuthorityIdentity, SocketIoLane, SocketIoLaneSlot, SystemTransitionBackend,
    TransitionBackend, WorkerDescriptorCache, platform,
};
use pkthere_socket_policy::SocketRole;
use socket2::{SockAddr, Socket};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

impl ManagedSocket {
    pub(super) fn clone_for_descriptor_cache(&self) -> io::Result<Self> {
        let scope = crate::authority::AuditedOperationScope::enter(
            crate::authority::OperationId::RefcountClone,
        )
        .map_err(io::Error::other)?;
        let clone = self.clone();
        drop(scope);
        Ok(clone)
    }

    pub(super) fn upgrade_for_descriptor_cache(&self) -> io::Result<Arc<Socket>> {
        let scope = crate::authority::AuditedOperationScope::enter(
            crate::authority::OperationId::RefcountUpgrade,
        )
        .map_err(io::Error::other)?;
        let descriptor = self.inner.descriptor.upgrade().ok_or_else(|| {
            io::Error::other(ManagedSocketError::DescriptorOwnershipLost {
                stage: "worker descriptor-cache refresh",
            })
        });
        drop(scope);
        descriptor
    }

    pub(super) fn socket_operation_scope(
        operation: crate::authority::OperationId,
    ) -> crate::authority::AuditedOperationScope {
        crate::authority::AuditedOperationScope::enter(operation).unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "socket operation scope {operation:?} rejected its held authorities: {error}"
            ))
        })
    }

    pub(super) fn backend_connect(&self, socket: &Socket, peer: &SockAddr) -> io::Result<()> {
        self.inner.backend.connect(socket, peer)
    }

    pub(super) fn backend_peer_addr(&self, socket: &Socket) -> io::Result<Option<SocketAddr>> {
        self.inner.backend.peer_addr(socket)
    }

    pub(super) fn backend_local_addr(&self, socket: &Socket) -> io::Result<SocketAddr> {
        self.inner.backend.local_addr(socket)
    }

    pub(crate) fn configure_worker_io_lanes(
        &self,
        worker_count: usize,
    ) -> Result<(), ManagedSocketError> {
        if worker_count == 0 {
            return Err(ManagedSocketError::ActiveIoExhausted);
        }
        let mut lanes = Vec::new();
        lanes
            .try_reserve_exact(worker_count)
            .map_err(|_| ManagedSocketError::ActiveIoExhausted)?;
        lanes.resize_with(worker_count, SocketIoLaneSlot::new);
        self.inner
            .worker_io_lanes
            .set(lanes.into_boxed_slice())
            .map_err(|_| ManagedSocketError::ActiveIoExhausted)
    }

    #[cfg(all(test, not(miri)))]
    pub(super) fn descriptor_reload_count(&self, lane: SocketIoLane) -> u64 {
        self.inner
            .io_lane(lane)
            .map_or(0, SocketIoLaneSlot::descriptor_reload_count)
    }

    #[cfg(all(test, not(miri)))]
    pub(super) fn descriptor_revocation_requested_for_test(&self, lane: SocketIoLane) -> u64 {
        self.inner
            .io_lane(lane)
            .map_or(0, |slot| slot.revocation_requested.load(Ordering::Acquire))
    }

    pub(super) fn transition_descriptor(
        &self,
        operation: AssociationOperation,
    ) -> Result<Arc<Socket>, ManagedSocketError> {
        let scope = crate::authority::AuditedOperationScope::enter(
            crate::authority::OperationId::RefcountUpgrade,
        )
        .map_err(|source| ManagedSocketError::DescriptorAuthorityLost { source })?;
        let descriptor =
            self.inner
                .descriptor
                .upgrade()
                .ok_or_else(|| ManagedSocketError::Retired {
                    operation,
                    epoch: self.topology_epoch(),
                });
        drop(scope);
        descriptor
    }

    pub(super) fn prepare_descriptor_retirement(&self) -> Result<(), ManagedSocketError> {
        self.inner
            .request_descriptor_cache_revocation_after_io_drain()
    }

    pub(super) fn retire_descriptor_after_revocation(&self) -> Result<bool, ManagedSocketError> {
        let descriptor = {
            let mut owner = self
                .inner
                .descriptor_owner
                .socket
                .lock()
                .map_err(|source| {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "managed socket descriptor-owner authority failed: {source}"
                    ));
                    ManagedSocketError::DescriptorAuthorityLost { source }
                })?;
            let Some(descriptor) = owner.as_ref() else {
                return Ok(false);
            };
            let strong_count = Arc::strong_count(descriptor);
            if strong_count != 1 {
                Err(strong_count)
            } else {
                Ok(owner
                    .take()
                    .ok_or(ManagedSocketError::DescriptorOwnershipLost {
                        stage: "descriptor-owner take",
                    })?)
            }
        };
        let descriptor = match descriptor {
            Ok(descriptor) => descriptor,
            Err(strong_count) => {
                let generation = self
                    .inner
                    .descriptor_revocation_generation
                    .load(Ordering::Acquire);
                let (registered, pending) = self.inner.descriptor_cache_evidence(generation);
                crate::runtime_support::publish_process_fatal(format_args!(
                    "managed socket descriptor ownership escaped after I/O drain: strong_count={strong_count}, registered_caches={registered}, pending_caches={pending}, revocation_generation={generation}"
                ));
                return Err(ManagedSocketError::DescriptorOwnershipEscaped { strong_count });
            }
        };
        let finalization = crate::authority::AuditedOperationScope::enter(
            crate::authority::OperationId::RefcountFinalize,
        )
        .map_err(|error| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "managed socket descriptor finalization crossed an unauthorized authority: {error}"
            ));
            ManagedSocketError::DescriptorAuthorityLost { source: error }
        })?;
        let descriptor = Arc::try_unwrap(descriptor).map_err(|escaped| {
            let strong_count = Arc::strong_count(&escaped);
            crate::runtime_support::publish_process_fatal(format_args!(
                "managed socket descriptor ownership escaped during finalization: strong_count={strong_count}"
            ));
            ManagedSocketError::DescriptorOwnershipEscaped { strong_count }
        })?;
        drop(finalization);

        let close = crate::authority::AuditedOperationScope::enter(
            crate::authority::OperationId::SocketDescriptorClose,
        )
        .map_err(|error| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "managed socket descriptor close crossed an unauthorized authority: {error}"
            ));
            ManagedSocketError::DescriptorAuthorityLost { source: error }
        })?;
        drop(descriptor);
        drop(close);
        Ok(true)
    }

    #[inline]
    pub(crate) fn same_descriptor(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(super) fn from_verified_realization(
        verified: super::realization::VerifiedRealizedSocket,
    ) -> Result<Self, ManagedSocketError> {
        let super::realization::VerifiedRealizedSocket {
            socket,
            policy,
            evidence,
            requirements,
        } = verified;
        Self::from_parts_checked(
            socket,
            Arc::new(SystemTransitionBackend),
            policy.peer_verification,
            requirements.expected_peer(),
            requirements.required_local_bind(),
            Some(evidence),
        )
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn from_unconnected(
        socket: Socket,
        peer_verification: PeerVerification,
        required_local_bind: SocketAddr,
    ) -> Result<Self, ManagedSocketError> {
        Self::with_backend_checked(
            socket,
            Arc::new(SystemTransitionBackend),
            peer_verification,
            None,
            required_local_bind,
        )
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn from_connected(
        socket: Socket,
        expected_peer: SocketAddr,
        required_local_bind: SocketAddr,
    ) -> Result<Self, ManagedSocketError> {
        Self::with_backend_checked(
            socket,
            Arc::new(SystemTransitionBackend),
            PeerVerification::RequirePeerAddr,
            Some(expected_peer),
            required_local_bind,
        )
    }

    #[cfg(all(test, not(miri)))]
    pub(super) fn with_backend_checked(
        socket: Socket,
        backend: Arc<dyn TransitionBackend>,
        peer_verification: PeerVerification,
        expected_peer: Option<SocketAddr>,
        required_local_bind: SocketAddr,
    ) -> Result<Self, ManagedSocketError> {
        Self::from_parts_checked(
            socket,
            backend,
            peer_verification,
            expected_peer,
            required_local_bind,
            None,
        )
    }

    fn from_parts_checked(
        socket: Socket,
        backend: Arc<dyn TransitionBackend>,
        peer_verification: PeerVerification,
        expected_peer: Option<SocketAddr>,
        required_local_bind: SocketAddr,
        realization_evidence: Option<super::realization::SocketEvidenceId>,
    ) -> Result<Self, ManagedSocketError> {
        {
            let _operation =
                Self::socket_operation_scope(crate::authority::OperationId::SocketConfigure);
            socket
                .set_nonblocking(true)
                .map_err(ManagedSocketError::NonblockingSetup)?;
        }
        let observed_peer = {
            let _operation =
                Self::socket_operation_scope(crate::authority::OperationId::SocketPeerInspection);
            backend
                .peer_addr(&socket)
                .map_err(ManagedSocketError::PeerInspection)?
        };
        if !peer_verification.accepts_observation(expected_peer, observed_peer) {
            return Err(ManagedSocketError::UnexpectedInitialAssociation {
                expected_peer,
                observed_peer,
            });
        }
        let association = match expected_peer {
            Some(peer) => AssociationState::Connected { peer, epoch: 0 },
            None => AssociationState::Unconnected { epoch: 0 },
        };
        let published_mode = match expected_peer {
            None => PublishedAssociationMode::Unconnected,
            Some(_) => PublishedAssociationMode::Connected,
        };
        let published_association = PublishedAssociation::new(published_mode, 0)
            .ok_or(ManagedSocketError::PublishedAssociationExhausted { epoch: 0 })?;
        let descriptor = Arc::new(socket);
        let descriptor_instance = Arc::as_ptr(&descriptor) as usize as u64;
        let inner = Arc::new(ManagedSocketInner {
            descriptor: Arc::downgrade(&descriptor),
            descriptor_owner: DescriptorOwner {
                socket: crate::authority::AuthorityMutex::new(
                    Some(Arc::clone(&descriptor)),
                    crate::authority::AuthorityInstance {
                        id: crate::authority::AuthorityId::SocketDescriptor,
                        flow: descriptor_instance,
                        direction: 0,
                        kind: 0,
                        session: 0,
                    },
                ),
            },
            realization_evidence,
            association_state: crate::authority::AuthorityMutex::new(
                super::AssociationAuthorityState::new(association, required_local_bind),
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::SocketAssociation,
                    flow: descriptor_instance,
                    direction: 0,
                    kind: 0,
                    session: 0,
                },
            ),
            published_association: crate::authority::AuthorityAtomic::new_u64(
                published_association.0,
                crate::authority::AtomicProtocolId::SocketGateAssociation,
            ),
            io_gate: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::SocketGateAssociation,
            ),
            descriptor_revocation_generation: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::DescriptorGeneration,
            ),
            worker_io_lanes: crate::authority::AuthorityOnceLock::new(),
            control_io_lane: SocketIoLaneSlot::new(),
            io_drain_wait: crate::authority::AuthorityMutex::new(
                (),
                crate::authority::AuthorityInstance::singleton(
                    crate::authority::AuthorityId::WaitCoordination,
                ),
            ),
            io_drained: crate::authority::AuthorityCondvar::new(
                crate::authority::WaitId::SocketIoDrain,
            ),
            authority_identity: crate::authority::AuthorityOnceLock::new(),
            authority_phase: crate::authority::AuthorityAtomic::new_u8(
                0,
                crate::authority::AtomicProtocolId::SocketGateAssociation,
            ),
            peer_verification,
            backend,
        });
        if inner.realization_evidence.is_none() && !cfg!(test) {
            return Err(ManagedSocketError::DescriptorOwnershipLost {
                stage: "managed socket publication without verified realization evidence",
            });
        }
        for authority in [
            inner.descriptor_owner.socket.prewarm(),
            inner.association_state.prewarm(),
            inner.io_drain_wait.prewarm(),
        ] {
            authority.map_err(|source| ManagedSocketError::DescriptorAuthorityLost { source })?;
        }
        inner.io_drained.prewarm();
        Ok(Self { inner })
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn has_verified_realization_evidence(&self) -> bool {
        self.inner.realization_evidence.is_some()
    }

    pub(crate) fn bind_authority_identity(
        &self,
        role: SocketRole,
        socket_slot: u32,
        generation: u64,
        unpublished_replacement: bool,
    ) -> Result<(), ManagedSocketError> {
        let identity = SocketAuthorityIdentity {
            flow: u64::from(socket_slot) + 1,
            direction: match role {
                SocketRole::Listener => 0,
                SocketRole::Upstream => 1,
            },
            generation,
        };
        let result = match self.inner.authority_identity.set(identity) {
            Ok(()) => Ok(()),
            Err(rejected) => self.inner.authority_identity.get().map_or_else(
                || {
                    Err(ManagedSocketError::DescriptorOwnershipLost {
                        stage: "socket authority identity publication",
                    })
                },
                |observed| {
                    if *observed == rejected {
                        Ok(())
                    } else {
                        Err(ManagedSocketError::AuthorityIdentityConflict {
                            expected_flow: rejected.flow,
                            expected_direction: rejected.direction,
                            expected_generation: rejected.generation,
                            observed_flow: observed.flow,
                            observed_direction: observed.direction,
                            observed_generation: observed.generation,
                        })
                    }
                },
            ),
        };
        if result.is_ok() {
            self.inner
                .authority_phase
                .store(u8::from(unpublished_replacement), Ordering::Release);
        }
        result
    }

    pub(super) fn authority_instance(
        &self,
        id: crate::authority::AuthorityId,
        kind: u8,
        fallback_session: u64,
    ) -> crate::authority::AuthorityInstance {
        self.inner.authority_identity.get().map_or(
            crate::authority::AuthorityInstance {
                id,
                flow: Arc::as_ptr(&self.inner) as usize as u64,
                direction: 0,
                kind,
                session: fallback_session,
            },
            |identity| crate::authority::AuthorityInstance {
                id,
                flow: identity.flow,
                direction: identity.direction,
                kind: if id == crate::authority::AuthorityId::SocketTopology {
                    self.inner.authority_phase.load(Ordering::Acquire)
                } else {
                    kind
                },
                session: identity.generation,
            },
        )
    }

    pub(super) fn descriptor_resource_generation(&self) -> Result<u64, ManagedSocketError> {
        self.inner
            .authority_identity
            .get()
            .map(|identity| identity.generation)
            .ok_or(ManagedSocketError::DescriptorOwnershipLost {
                stage: "managed socket descriptor generation",
            })
    }

    pub(super) fn mark_authority_identity_published(&self) {
        self.inner.authority_phase.store(0, Ordering::Release);
    }

    #[cfg(all(test, not(miri)))]
    pub(super) fn with_backend(
        socket: Socket,
        backend: Arc<dyn TransitionBackend>,
        peer_verification: PeerVerification,
        required_local_bind: SocketAddr,
    ) -> Self {
        let managed = Self::with_backend_checked(
            socket,
            backend,
            peer_verification,
            None,
            required_local_bind,
        )
        .expect("fake socket starts unconnected");
        managed
            .configure_worker_io_lanes(16)
            .expect("configure fake worker I/O lanes");
        managed
            .bind_authority_identity(SocketRole::Listener, 0, 1, false)
            .expect("bind fake socket authority identity");
        managed
    }

    #[inline]
    pub(crate) fn association(&self) -> AssociationState {
        self.lock_association_state().snapshot().0
    }

    #[inline]
    pub(crate) fn topology_epoch(&self) -> u64 {
        self.load_published_association().epoch()
    }

    #[inline]
    pub(crate) fn is_connected(&self) -> bool {
        matches!(
            self.load_published_association().mode(),
            PublishedAssociationMode::Connected
        )
    }

    #[inline]
    pub(crate) fn local_addr(&self) -> io::Result<SockAddr> {
        let lease = self.acquire_io_lease(IoKind::Receive, SocketIoLane::Control, None)?;
        let _operation =
            Self::socket_operation_scope(crate::authority::OperationId::SocketLocalInspection);
        lease.descriptor().local_addr()
    }

    pub(crate) fn acquire_send_lease<'socket>(
        &'socket self,
        cache: &'socket mut WorkerDescriptorCache,
    ) -> io::Result<ManagedSendLease<'socket>> {
        self.acquire_io_lease(IoKind::Send, cache.lane, Some(cache))
            .map(|authority| ManagedSendLease { authority })
    }

    pub(crate) fn wait_until_readable_or_wake<'socket>(
        &'socket self,
        cache: &'socket mut WorkerDescriptorCache,
        wake: &std::net::UdpSocket,
        timeout: Duration,
    ) -> io::Result<ManagedReadiness<'socket>> {
        let lease = self.acquire_io_lease(IoKind::Receive, cache.lane, Some(cache))?;
        let (packet_ready, wake_ready) = platform::wait_until_readable_or_wake(
            lease.descriptor(),
            wake,
            timeout.clamp(DATA_PLANE_POLL_MINIMUM, DATA_PLANE_POLL_FALLBACK),
        )?;
        Ok(ManagedReadiness {
            lease,
            packet_ready,
            wake_ready,
        })
    }

    pub(crate) fn acquire_control_send_lease(&self) -> io::Result<ManagedSendLease<'_>> {
        self.acquire_io_lease(IoKind::Send, SocketIoLane::Control, None)
            .map(|authority| ManagedSendLease { authority })
    }

    #[cfg(all(test, not(miri)))]
    pub(super) fn wait_until_readable_or_wake_control(
        &self,
        wake: &std::net::UdpSocket,
        timeout: Duration,
    ) -> io::Result<ManagedReadiness<'_>> {
        let lease = self.acquire_io_lease(IoKind::Receive, SocketIoLane::Control, None)?;
        let (packet_ready, wake_ready) = platform::wait_until_readable_or_wake(
            lease.descriptor(),
            wake,
            timeout.clamp(DATA_PLANE_POLL_MINIMUM, DATA_PLANE_POLL_FALLBACK),
        )?;
        Ok(ManagedReadiness {
            lease,
            packet_ready,
            wake_ready,
        })
    }
}
