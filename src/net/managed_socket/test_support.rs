#![cfg(all(test, not(miri)))]

use super::{
    AssociationOperation, IoSlice, ManagedSendResult, ManagedSocket, ManagedSocketError,
    ManagedWakePair, PeerVerification, ReceiveBuffer, ReceiveSyscall, ReceivedPacket, SockAddr,
    Socket, SocketAddr, SocketIoLane, TransitionBackend, io,
};
use socket2::{Domain, Protocol, Type};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) struct FakeState {
    pub(crate) calls: Vec<&'static str>,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) fail_connect: bool,
    pub(crate) fail_disconnect: bool,
    pub(crate) destination_required_on_send: bool,
    pub(crate) report_peer: bool,
    pub(crate) reported_peer_override: Option<SocketAddr>,
    pub(crate) local: SocketAddr,
    pub(crate) disconnect_local_after: Option<SocketAddr>,
    pub(crate) disconnect_mutates_on_error: bool,
    pub(crate) fail_peer_inspection_after_disconnect: bool,
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            peer: None,
            fail_connect: false,
            fail_disconnect: false,
            destination_required_on_send: false,
            report_peer: true,
            reported_peer_override: None,
            local: SocketAddr::from(([0, 0, 0, 0], 0)),
            disconnect_local_after: None,
            disconnect_mutates_on_error: false,
            fail_peer_inspection_after_disconnect: false,
        }
    }
}

#[derive(Default)]
pub(crate) struct FakeBackend {
    pub(crate) state: Mutex<FakeState>,
    pub(crate) flow_state: Option<Arc<crate::flow_state::FlowRuntimeState>>,
}

impl FakeBackend {
    fn assert_flow_mutex_free(&self) {
        if let Some(flow_state) = &self.flow_state {
            assert!(
                flow_state.client_flow_mutex_is_available_for_test(),
                "socket backend syscall observed the client-flow implementation mutex held"
            );
        }
    }
}

impl TransitionBackend for FakeBackend {
    fn connect(&self, _socket: &Socket, peer: &SockAddr) -> io::Result<()> {
        self.assert_flow_mutex_free();
        let mut state = self.state.lock().expect("fake state");
        state.calls.push("connect");
        if state.fail_connect {
            return Err(io::Error::other("injected connect failure"));
        }
        state.peer = peer.as_socket();
        Ok(())
    }

    fn disconnect(&self, _socket: &Socket) -> io::Result<()> {
        self.assert_flow_mutex_free();
        let mut state = self.state.lock().expect("fake state");
        state.calls.push("disconnect");
        if state.fail_disconnect {
            if state.disconnect_mutates_on_error {
                state.peer = None;
                if let Some(local) = state.disconnect_local_after {
                    state.local = local;
                }
            }
            return Err(io::Error::other("injected disconnect failure"));
        }
        state.peer = None;
        if let Some(local) = state.disconnect_local_after {
            state.local = local;
        }
        Ok(())
    }

    fn peer_addr(&self, _socket: &Socket) -> io::Result<Option<SocketAddr>> {
        self.assert_flow_mutex_free();
        let state = self.state.lock().expect("fake state");
        if state.fail_peer_inspection_after_disconnect && state.calls.last() == Some(&"disconnect")
        {
            return Err(io::Error::other("injected peer inspection failure"));
        }
        Ok(state
            .report_peer
            .then(|| state.reported_peer_override.or(state.peer))
            .flatten())
    }

    fn local_addr(&self, _socket: &Socket) -> io::Result<SocketAddr> {
        self.assert_flow_mutex_free();
        Ok(self.state.lock().expect("fake state").local)
    }

    fn send_connected(&self, _socket: &Socket, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        self.assert_flow_mutex_free();
        let mut state = self.state.lock().expect("fake state");
        state.calls.push("send");
        if state.destination_required_on_send {
            return Err(io::Error::from_raw_os_error(
                crate::net::managed_socket::DEST_ADDR_REQUIRED,
            ));
        }
        Ok(buffers.iter().map(|buffer| buffer.len()).sum())
    }

    fn send_unconnected(
        &self,
        _socket: &Socket,
        buffers: &[IoSlice<'_>],
        _destination: &SockAddr,
    ) -> io::Result<usize> {
        self.assert_flow_mutex_free();
        self.state.lock().expect("fake state").calls.push("send_to");
        Ok(buffers.iter().map(|buffer| buffer.len()).sum())
    }
}

pub(crate) fn fake_socket(backend: Arc<FakeBackend>) -> ManagedSocket {
    fake_socket_with_verification(backend, PeerVerification::RequirePeerAddr)
}

pub(crate) fn unconfigured_fake_socket(backend: Arc<FakeBackend>) -> ManagedSocket {
    let required_local_bind = backend.state.lock().expect("fake state").local;
    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("create test socket");
    ManagedSocket::with_backend_checked(
        socket,
        backend,
        PeerVerification::RequirePeerAddr,
        None,
        required_local_bind,
    )
    .expect("fake socket starts unconnected")
}

pub(crate) fn fake_socket_with_verification(
    backend: Arc<FakeBackend>,
    peer_verification: PeerVerification,
) -> ManagedSocket {
    let required_local_bind = backend.state.lock().expect("fake state").local;
    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("create test socket");
    ManagedSocket::with_backend(socket, backend, peer_verification, required_local_bind)
}

pub(crate) trait ProductionIoTestExt {
    fn acquire_topology_authority(
        &self,
        expected_epoch: u64,
        lane: SocketIoLane,
    ) -> io::Result<super::TopologyAuthorityLease<'_>>;

    fn send_packet(
        &self,
        buffers: &[IoSlice<'_>],
        destination: &SockAddr,
    ) -> io::Result<ManagedSendResult>;

    fn receive<'a, const CAPACITY: usize>(
        &self,
        syscall: ReceiveSyscall,
        buffer: &'a mut ReceiveBuffer<CAPACITY>,
    ) -> io::Result<ReceivedPacket<'a>>;

    fn receive_in_lane<'a, const CAPACITY: usize>(
        &self,
        lane: SocketIoLane,
        syscall: ReceiveSyscall,
        buffer: &'a mut ReceiveBuffer<CAPACITY>,
    ) -> io::Result<ReceivedPacket<'a>>;

    fn disconnect_connected(&self) -> Result<(), ManagedSocketError>;

    fn reconnect_connected(&self, new_peer: SocketAddr) -> Result<(), ManagedSocketError>;

    fn retire(&self) -> Result<(), ManagedSocketError>;

    fn transition_lock_available_for_test(&self) -> bool;

    fn topology_transitioning_for_test(&self) -> bool;

    fn topology_poisoned_for_test(&self) -> bool;

    fn io_lane_active_for_test(&self, lane: SocketIoLane) -> bool;
}

impl ProductionIoTestExt for ManagedSocket {
    fn acquire_topology_authority(
        &self,
        expected_epoch: u64,
        lane: SocketIoLane,
    ) -> io::Result<super::TopologyAuthorityLease<'_>> {
        if lane != SocketIoLane::Control {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker topology test authority requires an explicit worker cache",
            ));
        }
        let lease = self.acquire_io_lease(super::IoKind::Receive, lane, None)?;
        if lease.epoch() != expected_epoch {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "managed socket topology changed before test observation",
            ));
        }
        Ok(lease)
    }

    fn send_packet(
        &self,
        buffers: &[IoSlice<'_>],
        destination: &SockAddr,
    ) -> io::Result<ManagedSendResult> {
        self.acquire_control_send_lease()?
            .send_packet(buffers, destination)
    }

    fn receive<'a, const CAPACITY: usize>(
        &self,
        syscall: ReceiveSyscall,
        buffer: &'a mut ReceiveBuffer<CAPACITY>,
    ) -> io::Result<ReceivedPacket<'a>> {
        self.receive_in_lane(SocketIoLane::Control, syscall, buffer)
    }

    fn receive_in_lane<'a, const CAPACITY: usize>(
        &self,
        lane: SocketIoLane,
        syscall: ReceiveSyscall,
        buffer: &'a mut ReceiveBuffer<CAPACITY>,
    ) -> io::Result<ReceivedPacket<'a>> {
        let wake = ManagedWakePair::new()?;
        let observed = match lane {
            SocketIoLane::Control => self
                .wait_until_readable_or_wake_control(wake.receiver(), Duration::from_millis(50))?
                .receive_observed(buffer, syscall)?,
            SocketIoLane::Worker(worker_id) => {
                let mut cache = super::WorkerDescriptorCache::for_worker(worker_id);
                cache.reconcile(self)?;
                self.wait_until_readable_or_wake(
                    &mut cache,
                    wake.receiver(),
                    Duration::from_millis(50),
                )?
                .receive_observed(buffer, syscall)?
            }
        };
        observed
            .map(|(packet, _, _, _)| packet)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "test packet was not ready"))
    }

    fn disconnect_connected(&self) -> Result<(), ManagedSocketError> {
        let mut reservation = self.reserve_topology(AssociationOperation::Disconnect)?;
        reservation.disconnect_connected()?;
        reservation.commit()
    }

    fn reconnect_connected(&self, new_peer: SocketAddr) -> Result<(), ManagedSocketError> {
        let mut reservation = self.reserve_topology(AssociationOperation::Reconnect)?;
        reservation.reconnect_connected(new_peer)?;
        reservation.commit()
    }

    fn retire(&self) -> Result<(), ManagedSocketError> {
        if matches!(self.association(), super::AssociationState::Retired { .. }) {
            return Ok(());
        }
        self.reserve_topology(AssociationOperation::Replace)?
            .into_retired_for_replacement()?
            .commit()
    }

    fn transition_lock_available_for_test(&self) -> bool {
        self.inner.association_state.is_available_for_test()
    }

    fn topology_transitioning_for_test(&self) -> bool {
        self.load_published_association().mode() == super::PublishedAssociationMode::Transitioning
    }

    fn topology_poisoned_for_test(&self) -> bool {
        self.load_published_association().mode() == super::PublishedAssociationMode::Poisoned
    }

    fn io_lane_active_for_test(&self, lane: SocketIoLane) -> bool {
        self.inner.io_lane(lane).is_some_and(|slot| {
            crate::atomic_core::epoch_lane_is_active(slot.active_epoch.load(Ordering::Acquire))
        })
    }
}
