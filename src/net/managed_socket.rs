use pkthere_socket_policy::{PeerVerification, ReceiveSyscall};
use socket2::{SockAddr, Socket};
use std::fmt;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

const DATA_PLANE_POLL_FALLBACK: Duration = Duration::from_millis(50);
const DATA_PLANE_POLL_MINIMUM: Duration = Duration::from_millis(1);
const TOPOLOGY_IO_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const IO_GATE_CLOSED: u64 = 1_u64 << (u64::BITS - 1);
#[cfg(unix)]
pub(crate) const DEST_ADDR_REQUIRED: i32 = libc::EDESTADDRREQ;
#[cfg(windows)]
pub(crate) const DEST_ADDR_REQUIRED: i32 = 10039; // WSAEDESTADDRREQ
pub(crate) const SOCKET_IO_LANE_BYTES: usize = size_of::<SocketIoLaneSlot>();

pub(crate) fn descriptor_cache_reconcile_is_retryable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

mod association;
mod association_reservation;
mod association_socket_ops;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod association_state_loom;
mod error;
mod platform;
pub(in crate::net) mod realization;
mod receive;
mod retirement_core;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod retirement_core_loom;
#[cfg(all(test, not(miri)))]
pub(crate) mod test_support;
mod types;
mod wake;
pub(crate) use error::{AssociationStale, ManagedSocketError};
pub(crate) use receive::{ReceiveBuffer, ReceivedPacket};
pub(crate) use wake::ManagedWakePair;

pub(crate) use types::{
    AssociationOperation, AssociationState, ClearTransitionPhase, DisconnectOutcome,
    ManagedSendPath, ManagedSendResult,
};
use types::{
    IoLeaseAcquireError, PublishedAssociation, PublishedAssociationMode, next_association_epoch,
    peer_absent_error, peer_network_address_matches,
};

trait TransitionBackend: Send + Sync {
    fn connect(&self, socket: &Socket, peer: &SockAddr) -> io::Result<()>;
    fn disconnect(&self, socket: &Socket) -> io::Result<()>;
    fn peer_addr(&self, socket: &Socket) -> io::Result<Option<SocketAddr>>;
    fn local_addr(&self, socket: &Socket) -> io::Result<SocketAddr> {
        let _operation = crate::authority::audited_operation(
            crate::authority::OperationId::SocketLocalInspection,
        );
        socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("managed socket has a non-INET local address"))
    }

    fn send_connected(&self, socket: &Socket, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        let _operation =
            crate::authority::audited_operation(crate::authority::OperationId::SocketSend);
        match buffers {
            [only] => socket.send(only),
            _ => socket.send_vectored(buffers),
        }
    }

    fn send_unconnected(
        &self,
        socket: &Socket,
        buffers: &[IoSlice<'_>],
        destination: &SockAddr,
    ) -> io::Result<usize> {
        let _operation =
            crate::authority::audited_operation(crate::authority::OperationId::SocketSend);
        match buffers {
            [only] => socket.send_to(only, destination),
            _ => socket.send_to_vectored(buffers, destination),
        }
    }
}

struct SystemTransitionBackend;

impl TransitionBackend for SystemTransitionBackend {
    fn connect(&self, socket: &Socket, peer: &SockAddr) -> io::Result<()> {
        let _operation =
            crate::authority::audited_operation(crate::authority::OperationId::SocketConnect);
        socket.connect(peer)
    }

    fn disconnect(&self, socket: &Socket) -> io::Result<()> {
        platform::disconnect(socket)
    }

    fn peer_addr(&self, socket: &Socket) -> io::Result<Option<SocketAddr>> {
        let _operation = crate::authority::audited_operation(
            crate::authority::OperationId::SocketPeerInspection,
        );
        match socket.peer_addr() {
            Ok(peer) => Ok(peer.as_socket()),
            Err(error) if peer_absent_error(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

struct DescriptorOwner {
    socket: crate::authority::AuthorityMutex<
        crate::authority::tags::SocketDescriptor,
        Option<Arc<Socket>>,
    >,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AssociationAuthorityState {
    association: AssociationState,
    required_local_bind: SocketAddr,
}

impl AssociationAuthorityState {
    const fn new(association: AssociationState, required_local_bind: SocketAddr) -> Self {
        Self {
            association,
            required_local_bind,
        }
    }

    const fn snapshot(&self) -> (AssociationState, SocketAddr) {
        (self.association, self.required_local_bind)
    }

    fn publish(&mut self, association: AssociationState, required_local_bind: SocketAddr) {
        self.association = association;
        self.required_local_bind = required_local_bind;
    }
}

struct ManagedSocketInner {
    descriptor: Weak<Socket>,
    descriptor_owner: DescriptorOwner,
    realization_evidence: Option<realization::SocketEvidenceId>,
    association_state: crate::authority::AuthorityMutex<
        crate::authority::tags::SocketAssociation,
        AssociationAuthorityState,
    >,
    published_association:
        crate::authority::AuthorityAtomic<crate::authority::tags::SocketTopology, AtomicU64>,
    io_gate: crate::authority::AuthorityAtomic<crate::authority::tags::SocketTopology, AtomicU64>,
    descriptor_revocation_generation:
        crate::authority::AuthorityAtomic<crate::authority::tags::SocketTopology, AtomicU64>,
    worker_io_lanes: crate::authority::AuthorityOnceLock<
        crate::authority::tags::SocketTopology,
        Box<[SocketIoLaneSlot]>,
    >,
    control_io_lane: SocketIoLaneSlot,
    io_drain_wait: crate::authority::AuthorityMutex<crate::authority::tags::WaitCoordination, ()>,
    io_drained: crate::authority::AuthorityCondvar<crate::authority::tags::WaitCoordination>,
    authority_identity: crate::authority::AuthorityOnceLock<
        crate::authority::tags::SocketTopology,
        SocketAuthorityIdentity,
    >,
    authority_phase:
        crate::authority::AuthorityAtomic<crate::authority::tags::SocketTopology, AtomicU8>,
    peer_verification: PeerVerification,
    backend: Arc<dyn TransitionBackend>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketAuthorityIdentity {
    flow: u64,
    direction: u8,
    generation: u64,
}

impl ManagedSocketInner {
    fn descriptor_cache_evidence(&self, generation: u64) -> (usize, usize) {
        self.worker_io_lanes.get().map_or((0, 0), |lanes| {
            lanes
                .iter()
                .fold((0usize, 0usize), |(registered, pending), lane| {
                    let is_registered = lane.cache_registered.load(Ordering::Acquire);
                    let is_pending = is_registered
                        && lane.revocation_acknowledged.load(Ordering::Acquire) < generation;
                    (
                        registered + usize::from(is_registered),
                        pending + usize::from(is_pending),
                    )
                })
        })
    }

    #[inline]
    fn io_lane(&self, lane: SocketIoLane) -> Option<&SocketIoLaneSlot> {
        match lane {
            SocketIoLane::Worker(index) => self.worker_io_lanes.get()?.get(index),
            SocketIoLane::Control => Some(&self.control_io_lane),
        }
    }

    fn active_io_count(&self) -> usize {
        let worker_count = self.worker_io_lanes.get().map_or(0, |lanes| {
            lanes
                .iter()
                .filter(|lane| {
                    crate::atomic_core::epoch_lane_is_active(
                        lane.active_epoch.load(Ordering::Acquire),
                    )
                })
                .count()
        });
        worker_count
            + usize::from(crate::atomic_core::epoch_lane_is_active(
                self.control_io_lane.active_epoch.load(Ordering::Acquire),
            ))
    }

    fn reserve_idle_io_lanes(&self) -> bool {
        let mut all_reserved = true;
        if let Some(lanes) = self.worker_io_lanes.get() {
            for lane in lanes {
                all_reserved &=
                    crate::atomic_core::reserve_epoch_lane_for_writer(&lane.active_epoch)
                        .unwrap_or(false);
            }
        }
        all_reserved
            & crate::atomic_core::reserve_epoch_lane_for_writer(&self.control_io_lane.active_epoch)
                .unwrap_or(false)
    }

    fn release_reserved_io_lanes(&self) -> Result<(), ()> {
        if let Some(lanes) = self.worker_io_lanes.get() {
            for lane in lanes {
                if lane.active_epoch.load(Ordering::Acquire)
                    == crate::atomic_core::WRITER_RESERVED_EPOCH_LANE
                {
                    crate::atomic_core::release_writer_epoch_lane(&lane.active_epoch)
                        .map_err(|_| ())?;
                }
            }
        }
        if self.control_io_lane.active_epoch.load(Ordering::Acquire)
            == crate::atomic_core::WRITER_RESERVED_EPOCH_LANE
        {
            crate::atomic_core::release_writer_epoch_lane(&self.control_io_lane.active_epoch)
                .map_err(|_| ())?;
        }
        Ok(())
    }

    fn request_descriptor_cache_revocation_after_io_drain(&self) -> Result<(), ManagedSocketError> {
        let gate = self.io_gate.load(Ordering::Acquire);
        if gate & IO_GATE_CLOSED == 0 {
            return Err(ManagedSocketError::TopologyQuiescenceLost {
                operation: AssociationOperation::Replace,
                active_io: self.active_io_count(),
                epoch: gate,
            });
        }
        let active_io = self.active_io_count();
        if active_io != 0 {
            return Err(ManagedSocketError::TopologyQuiescenceLost {
                operation: AssociationOperation::Replace,
                active_io,
                epoch: gate & !IO_GATE_CLOSED,
            });
        }
        let revocation_generation = self
            .descriptor_revocation_generation
            .try_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map_err(|_| ManagedSocketError::DescriptorRevocationExhausted)?
            .checked_add(1)
            .ok_or(ManagedSocketError::DescriptorRevocationExhausted)?;
        if let Some(lanes) = self.worker_io_lanes.get() {
            for lane in lanes {
                crate::atomic_core::request_descriptor_cache_revocation(
                    &lane.cache_registered,
                    &lane.revocation_requested,
                    revocation_generation,
                );
            }
        }
        let deadline = std::time::Instant::now() + TOPOLOGY_IO_DRAIN_TIMEOUT;
        let mut wait = self.io_drain_wait.lock().map_err(|source| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "descriptor-cache revocation wait authority failed: {source}"
            ));
            ManagedSocketError::DescriptorAuthorityLost { source }
        })?;
        loop {
            let pending = self.worker_io_lanes.get().is_some_and(|lanes| {
                lanes.iter().any(|lane| {
                    crate::atomic_core::descriptor_cache_revocation_pending(
                        &lane.cache_registered,
                        &lane.revocation_acknowledged,
                        revocation_generation,
                    )
                })
            });
            if !pending {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(ManagedSocketError::DescriptorRevocationTimedOut {
                    generation: revocation_generation,
                });
            }
            let (next_wait, timed_out) = self
                .io_drained
                .wait_until_as(
                    wait,
                    deadline,
                    crate::authority::WaitId::DescriptorRevocation,
                )
                .map_err(|source| {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "descriptor-cache revocation wait failed: {source}"
                    ));
                    ManagedSocketError::DescriptorAuthorityLost { source }
                })?;
            wait = next_wait;
            if timed_out {
                return Err(ManagedSocketError::DescriptorRevocationTimedOut {
                    generation: revocation_generation,
                });
            }
        }
    }
}

pub(crate) struct TopologyAuthorityLease<'socket> {
    descriptor: LeaseDescriptor<'socket>,
    published: PublishedAssociation,
    _kind: IoKind,
    _authority: crate::authority::AuthorityScope<crate::authority::tags::SocketIo>,
    _active_io: ActiveIoGuard<'socket>,
}

struct ActiveIoGuard<'socket> {
    inner: &'socket ManagedSocketInner,
    lane: SocketIoLane,
    epoch: u64,
}

impl ActiveIoGuard<'_> {
    #[inline]
    fn inner(&self) -> &ManagedSocketInner {
        self.inner
    }
}

enum LeaseDescriptor<'socket> {
    Worker(&'socket Socket),
    Control(Arc<Socket>),
}

#[repr(align(128))]
struct SocketIoLaneSlot {
    active_epoch: crate::authority::AuthorityAtomic<crate::authority::tags::SocketIo, AtomicU64>,
    cache_registered:
        crate::authority::AuthorityAtomic<crate::authority::tags::SocketTopology, AtomicBool>,
    revocation_requested:
        crate::authority::AuthorityAtomic<crate::authority::tags::SocketTopology, AtomicU64>,
    revocation_acknowledged:
        crate::authority::AuthorityAtomic<crate::authority::tags::SocketTopology, AtomicU64>,
    #[cfg(any(test, feature = "authority-audit"))]
    descriptor_refreshes:
        crate::authority::AuthorityAtomic<crate::authority::tags::DiagnosticCounter, AtomicU64>,
}

impl SocketIoLaneSlot {
    const fn new() -> Self {
        Self {
            active_epoch: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::SocketGateAssociation,
            ),
            cache_registered: crate::authority::AuthorityAtomic::new_bool(
                false,
                crate::authority::AtomicProtocolId::DescriptorCacheOwnership,
            ),
            revocation_requested: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::DescriptorGeneration,
            ),
            revocation_acknowledged: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::DescriptorGeneration,
            ),
            #[cfg(any(test, feature = "authority-audit"))]
            descriptor_refreshes: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::DiagnosticCounter,
            ),
        }
    }

    #[cfg(all(test, not(miri)))]
    fn descriptor_reload_count(&self) -> u64 {
        self.descriptor_refreshes.load(Ordering::Relaxed)
    }
}

/// Strong descriptor cache structurally owned by one forwarding worker.
///
/// Mutation requires `&mut self`; shared socket state contains only the
/// revocation request and acknowledgement atomics. A cache may be reused for
/// successive socket generations by the same non-reusable worker lane.
pub(crate) struct WorkerDescriptorCache {
    lane: SocketIoLane,
    socket: Option<ManagedSocket>,
    core: crate::atomic_core::DescriptorCacheCore<Arc<Socket>>,
}

impl WorkerDescriptorCache {
    pub(crate) const fn for_worker(worker_id: usize) -> Self {
        Self {
            lane: SocketIoLane::Worker(worker_id),
            socket: None,
            core: crate::atomic_core::DescriptorCacheCore::new(),
        }
    }

    fn same_socket(&self, socket: &ManagedSocket) -> bool {
        self.socket
            .as_ref()
            .is_some_and(|cached| cached.same_descriptor(socket))
    }

    fn acknowledge_pending(&mut self) -> io::Result<bool> {
        if !self.core.is_registered() {
            return Ok(false);
        }
        let Some(socket) = self.socket.as_ref() else {
            return Ok(false);
        };
        let slot = socket
            .inner
            .io_lane(self.lane)
            .ok_or_else(|| io::Error::other(ManagedSocketError::ActiveIoExhausted))?;
        if !self
            .core
            .acknowledge(&slot.revocation_requested, &slot.revocation_acknowledged)
        {
            return Ok(false);
        }
        let wait = socket.inner.io_drain_wait.lock().map_err(|source| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "descriptor-cache acknowledgement authority failed: {source}"
            ));
            io::Error::other(ManagedSocketError::DescriptorAuthorityLost { source })
        })?;
        socket.inner.io_drained.notify_all();
        drop(wait);
        Ok(true)
    }

    /// Services only an already-published revocation request. This operation
    /// can drop the worker's cached descriptor and acknowledge the writer, but
    /// it never acquires or publishes a replacement descriptor.
    pub(crate) fn service_revocation(&mut self) -> io::Result<bool> {
        self.acknowledge_pending()
    }

    fn release_current(&mut self) -> io::Result<()> {
        self.acknowledge_pending()?;
        if self.core.is_registered()
            && let Some(socket) = self.socket.as_ref()
            && let Some(slot) = socket.inner.io_lane(self.lane)
        {
            self.core.unregister(&slot.cache_registered);
            let wait = socket.inner.io_drain_wait.lock().map_err(|source| {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "descriptor-cache unregister wait authority failed: {source}"
                ));
                io::Error::other(ManagedSocketError::DescriptorAuthorityLost { source })
            })?;
            socket.inner.io_drained.notify_all();
            drop(wait);
        } else {
            if self.core.is_registered() {
                return Err(io::Error::other(
                    "descriptor cache registration has no owning socket lane",
                ));
            }
        }
        self.socket = None;
        Ok(())
    }

    pub(crate) fn reconcile(&mut self, socket: &ManagedSocket) -> io::Result<()> {
        let resource_generation = socket
            .descriptor_resource_generation()
            .map_err(io::Error::other)?;
        if self.same_socket(socket) {
            self.acknowledge_pending()?;
        } else if self.socket.is_some() {
            self.release_current()?;
        }
        if !self.same_socket(socket) {
            self.socket = Some(socket.clone_for_descriptor_cache()?);
        }
        if !self.core.has_descriptor() {
            // A worker may loop again after acknowledging revocation while the
            // flow/topology transaction is still closed. Refreshing here would
            // recreate a strong owner after the manager observed every cache
            // acknowledgement and race descriptor retirement.
            let slot = socket
                .inner
                .io_lane(self.lane)
                .ok_or_else(|| io::Error::other(ManagedSocketError::ActiveIoExhausted))?;
            match self.core.register_with(
                &slot.cache_registered,
                &socket.inner.io_gate,
                IO_GATE_CLOSED,
                resource_generation,
                || socket.upgrade_for_descriptor_cache(),
            )? {
                crate::atomic_core::DescriptorCacheRegistration::Registered => {}
                crate::atomic_core::DescriptorCacheRegistration::GateClosed => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "managed socket topology is transitioning",
                    ));
                }
                crate::atomic_core::DescriptorCacheRegistration::SlotOccupied => {
                    return Err(io::Error::other(
                        "descriptor-cache lane already has a distinct registered owner",
                    ));
                }
            }
            #[cfg(any(test, feature = "authority-audit"))]
            slot.descriptor_refreshes.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn descriptor<'cache>(
        &'cache mut self,
        socket: &ManagedSocket,
        topology_epoch: u64,
    ) -> Result<&'cache Socket, ManagedSocketError> {
        if !self.same_socket(socket) || !self.core.has_descriptor() {
            return Err(ManagedSocketError::DescriptorOwnershipLost {
                stage: "worker descriptor cache must be reconciled before socket I/O",
            });
        }
        let resource_generation = socket.descriptor_resource_generation()?;
        self.core
            .descriptor_for_io(resource_generation, topology_epoch)
            .map(Arc::as_ref)
            .ok_or(ManagedSocketError::DescriptorOwnershipLost {
                stage: "worker descriptor-cache borrow",
            })
    }
}

impl Drop for WorkerDescriptorCache {
    fn drop(&mut self) {
        if let Err(error) = self.release_current() {
            crate::runtime_support::publish_process_fatal(format_args!(
                "worker descriptor-cache teardown failed: {error}"
            ));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketIoLane {
    Worker(usize),
    Control,
}

fn release_socket_io_epoch(
    lane: SocketIoLane,
    slot: &SocketIoLaneSlot,
    epoch: u64,
) -> Result<(), crate::atomic_core::LaneAdmissionError> {
    match lane {
        SocketIoLane::Worker(_) => {
            crate::atomic_core::release_epoch_lane(&slot.active_epoch, epoch)
        }
        SocketIoLane::Control => {
            crate::atomic_core::release_contended_epoch_lane(&slot.active_epoch, epoch)
        }
    }
}

pub(crate) struct ManagedReadiness<'socket> {
    lease: TopologyAuthorityLease<'socket>,
    packet_ready: bool,
    wake_ready: bool,
}

impl ManagedReadiness<'_> {
    pub(crate) fn connected(&self) -> bool {
        self.lease.connected()
    }

    pub(crate) fn receive_observed<'a, const CAPACITY: usize>(
        self,
        buffer: &'a mut ReceiveBuffer<CAPACITY>,
        syscall: ReceiveSyscall,
    ) -> io::Result<Option<(ReceivedPacket<'a>, std::time::Instant, bool, u64)>> {
        if !self.packet_ready {
            return Ok(None);
        }
        let connected = self.lease.connected();
        let topology_epoch = self.lease.epoch();
        let packet = receive::receive(self.lease.descriptor(), syscall, buffer)?;
        let received_at = std::time::Instant::now();
        Ok(Some((packet, received_at, connected, topology_epoch)))
    }
}

pub(crate) struct ManagedSendLease<'socket> {
    authority: TopologyAuthorityLease<'socket>,
}

impl ManagedSendLease<'_> {
    pub(crate) fn send_packet(
        &self,
        buffers: &[IoSlice<'_>],
        destination: &SockAddr,
    ) -> io::Result<ManagedSendResult> {
        match self.authority.published.mode() {
            PublishedAssociationMode::Connected => self
                .authority
                ._active_io
                .inner()
                .backend
                .send_connected(self.authority.descriptor(), buffers)
                .map(|length| ManagedSendResult {
                    length,
                    path: ManagedSendPath::Connected,
                })
                .map_err(|error| {
                    if error.raw_os_error() == Some(DEST_ADDR_REQUIRED) {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            AssociationStale::new(self.authority.epoch()),
                        )
                    } else {
                        error
                    }
                }),
            PublishedAssociationMode::Unconnected => self
                .authority
                ._active_io
                .inner()
                .backend
                .send_unconnected(self.authority.descriptor(), buffers, destination)
                .map(|length| ManagedSendResult {
                    length,
                    path: ManagedSendPath::Unconnected,
                }),
            PublishedAssociationMode::Poisoned => Err(io::Error::other(
                "send rejected: managed socket is poisoned",
            )),
            PublishedAssociationMode::Retired => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "send rejected: managed socket is retired",
            )),
            PublishedAssociationMode::Transitioning => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "send rejected while managed socket topology is transitioning",
            )),
        }
    }
}

impl ManagedReadiness<'_> {
    #[inline]
    pub(crate) const fn flags(&self) -> (bool, bool) {
        (self.packet_ready, self.wake_ready)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IoKind {
    Receive,
    Send,
}

impl TopologyAuthorityLease<'_> {
    #[inline]
    fn descriptor(&self) -> &Socket {
        match &self.descriptor {
            LeaseDescriptor::Worker(descriptor) => descriptor,
            LeaseDescriptor::Control(descriptor) => descriptor,
        }
    }

    #[inline]
    fn connected(&self) -> bool {
        matches!(self.published.mode(), PublishedAssociationMode::Connected)
    }

    #[inline]
    pub(crate) const fn epoch(&self) -> u64 {
        self.published.epoch()
    }
}

impl Drop for ActiveIoGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        let inner = self.inner();
        let Some(lane) = inner.io_lane(self.lane) else {
            crate::runtime_support::publish_process_fatal(format_args!(
                "managed socket I/O lane disappeared during release"
            ));
            return;
        };
        if release_socket_io_epoch(self.lane, lane, self.epoch).is_err() {
            crate::runtime_support::publish_process_fatal(format_args!(
                "managed socket I/O lane ownership was lost during release"
            ));
            return;
        }
        if inner.io_gate.load(Ordering::Acquire) & IO_GATE_CLOSED != 0 {
            let _wait = inner.io_drain_wait.lock().unwrap_or_else(|error| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "socket I/O drain authority failed during release: {error}"
                ))
            });
            inner.io_drained.notify_all();
        }
    }
}

/// Shared logical authority for one descriptor and its kernel association.
///
/// Clones retain only a weak descriptor reference. The detachable owner slot
/// is the sole persistent strong descriptor owner, so retiring the slot closes
/// the kernel descriptor even while stale logical handles remain alive.
#[derive(Clone)]
pub(crate) struct ManagedSocket {
    inner: Arc<ManagedSocketInner>,
}

/// Unique worker-owned receive capability for one managed descriptor.
///
/// This type is intentionally not `Clone`. Senders may share `ManagedSocket`,
/// while production receive ownership remains with exactly one worker loop.
pub(crate) struct ManagedReceiver {
    socket: ManagedSocket,
}

/// Exclusive topology reservation used while preparing a replacement.
///
/// The reservation closes I/O admission and drains existing bounded syscalls,
/// but does not retire the descriptor until the replacement is ready. Dropping
/// an uncommitted reservation reopens the original association at a new epoch,
/// so stale authorities cannot become valid again through rollback.
#[derive(Debug)]
pub(crate) struct TopologyReservation {
    socket: ManagedSocket,
    previous: AssociationState,
    previous_local_bind: SocketAddr,
    epoch: u64,
    operation: AssociationOperation,
    staged: Option<AssociationState>,
    staged_local_bind: Option<SocketAddr>,
    phase: ClearTransitionPhase,
    completed: bool,
    _authority: Option<crate::authority::AuthorityScope<crate::authority::tags::SocketTopology>>,
}

/// Irreversible topology ownership after the persistent descriptor was taken
/// and retired for replacement.
///
/// This typestate intentionally exposes no rollback operation. The only
/// completion is publication of the retired old topology; replacement
/// publication is owned separately by the new descriptor reservation.
pub(crate) type RetiredTopologyReservation =
    retirement_core::RetiredSocketTransaction<TopologyReservation>;

pub(crate) type ReplacementBoundTopologyReservation =
    retirement_core::ReplacementBoundSocketTransaction<TopologyReservation>;

/// Releases audit co-hold scopes for a complete sorted topology batch in the
/// only valid LIFO order. The closed socket gates remain the actual exclusive
/// transaction authority after this operation.
pub(crate) fn park_topology_reservation_batch(
    reservations: &mut [Option<TopologyReservation>],
) -> Result<(), ManagedSocketError> {
    TopologyBatchOrder::try_finish_reverse(
        reservations.iter_mut().filter_map(Option::as_mut),
        |step, reservation| reservation.park_authority(step),
    )
}

impl ManagedReceiver {
    pub(crate) fn new(socket: &ManagedSocket) -> Self {
        Self {
            socket: socket.clone(),
        }
    }

    pub(crate) fn topology_epoch(&self) -> u64 {
        self.socket.topology_epoch()
    }

    pub(crate) fn reconcile_descriptor_cache(
        &self,
        cache: &mut WorkerDescriptorCache,
    ) -> io::Result<()> {
        cache.reconcile(&self.socket)
    }

    pub(crate) fn wait_until_readable_or_wake<'socket>(
        &'socket self,
        cache: &'socket mut WorkerDescriptorCache,
        wake: &std::net::UdpSocket,
        timeout: Duration,
    ) -> io::Result<ManagedReadiness<'socket>> {
        self.socket
            .wait_until_readable_or_wake(cache, wake, timeout)
    }
}

impl fmt::Debug for ManagedSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSocket")
            .field("association", &self.association())
            .finish_non_exhaustive()
    }
}

mod api;
mod topology_batch;

pub(in crate::net) use topology_batch::{
    TopologyBatchOrder, TopologyBatchStep, TopologyReservationBatch,
};

#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod topology_batch_loom;

#[cfg(all(test, not(miri)))]
mod tests;

#[cfg(all(test, not(miri)))]
mod send_tests;

#[cfg(all(test, not(miri)))]
mod constructor_tests;
#[cfg(all(test, not(miri)))]
mod receive_tests;

#[cfg(all(test, not(miri)))]
mod concurrency_tests;
#[cfg(test)]
mod receive_unit_tests;
#[cfg(test)]
mod wake_unit_tests;
