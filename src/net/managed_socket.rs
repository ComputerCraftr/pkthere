use crate::net::socket_errors::DEST_ADDR_REQUIRED;
use pkthere_socket_policy::{PeerVerification, ReceiveSyscall};
use socket2::{SockAddr, Socket};
use std::fmt;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

mod error;
mod platform;
mod receive;
pub(crate) use error::ManagedSocketError;
pub(crate) use receive::{ReceiveBuffer, ReceivedPacket};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedSendPath {
    Connected,
    Unconnected,
    RetriedUnconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManagedSendResult {
    pub(crate) length: usize,
    pub(crate) path: ManagedSendPath,
}

impl ManagedSendResult {
    pub(crate) const fn used_unconnected_send(self) -> bool {
        !matches!(self.path, ManagedSendPath::Connected)
    }

    pub(crate) const fn association_changed(self) -> bool {
        matches!(self.path, ManagedSendPath::RetriedUnconnected)
    }
}

/// The tracked kernel association of one socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssociationState {
    Unconnected {
        epoch: u64,
    },
    Connected {
        peer: SocketAddr,
        epoch: u64,
    },
    Poisoned {
        operation: AssociationOperation,
        previous_peer: Option<SocketAddr>,
        epoch: u64,
    },
}

impl AssociationState {
    #[inline]
    pub(crate) const fn is_connected(self) -> bool {
        matches!(self, Self::Connected { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssociationOperation {
    Connect,
    Disconnect,
    Reconnect,
}

trait TransitionBackend: Send + Sync {
    fn connect(&self, socket: &Socket, peer: &SockAddr) -> io::Result<()>;
    fn disconnect(&self, socket: &Socket) -> io::Result<()>;
    fn peer_addr(&self, socket: &Socket) -> io::Result<Option<SocketAddr>>;

    fn send_connected(&self, socket: &Socket, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
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
        match buffers {
            [only] => socket.send_to(only, destination),
            _ => socket.send_to_vectored(buffers, destination),
        }
    }
}

struct SystemTransitionBackend;

impl TransitionBackend for SystemTransitionBackend {
    fn connect(&self, socket: &Socket, peer: &SockAddr) -> io::Result<()> {
        socket.connect(peer)
    }

    fn disconnect(&self, socket: &Socket) -> io::Result<()> {
        platform::disconnect(socket)
    }

    fn peer_addr(&self, socket: &Socket) -> io::Result<Option<SocketAddr>> {
        match socket.peer_addr() {
            Ok(peer) => Ok(peer.as_socket()),
            Err(error) if peer_absent_error(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

struct ManagedSocketInner {
    socket: Socket,
    association: Mutex<AssociationState>,
    peer_verification: PeerVerification,
    backend: Arc<dyn TransitionBackend>,
}

/// Shared ownership of one descriptor and its kernel association state.
///
/// Cloning this value never duplicates the OS descriptor. Socket policy
/// decides which transition should occur; this type makes the completed
/// kernel transition authoritative for current association state.
#[derive(Clone)]
pub(crate) struct ManagedSocket {
    inner: Arc<ManagedSocketInner>,
}

impl fmt::Debug for ManagedSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSocket")
            .field("association", &self.association())
            .finish_non_exhaustive()
    }
}

impl ManagedSocket {
    pub(crate) fn from_unconnected(
        socket: Socket,
        peer_verification: PeerVerification,
    ) -> Result<Self, ManagedSocketError> {
        Self::with_backend_checked(
            socket,
            Arc::new(SystemTransitionBackend),
            peer_verification,
            None,
        )
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn from_connected(
        socket: Socket,
        expected_peer: SocketAddr,
    ) -> Result<Self, ManagedSocketError> {
        Self::with_backend_checked(
            socket,
            Arc::new(SystemTransitionBackend),
            PeerVerification::RequirePeerAddr,
            Some(expected_peer),
        )
    }

    fn with_backend_checked(
        socket: Socket,
        backend: Arc<dyn TransitionBackend>,
        peer_verification: PeerVerification,
        expected_peer: Option<SocketAddr>,
    ) -> Result<Self, ManagedSocketError> {
        let observed_peer = backend
            .peer_addr(&socket)
            .map_err(ManagedSocketError::PeerInspection)?;
        if observed_peer != expected_peer {
            return Err(ManagedSocketError::UnexpectedInitialAssociation {
                expected_peer,
                observed_peer,
            });
        }
        let association = match expected_peer {
            Some(peer) => AssociationState::Connected { peer, epoch: 0 },
            None => AssociationState::Unconnected { epoch: 0 },
        };
        Ok(Self {
            inner: Arc::new(ManagedSocketInner {
                socket,
                association: Mutex::new(association),
                peer_verification,
                backend,
            }),
        })
    }

    #[cfg(all(test, not(miri)))]
    fn with_backend(
        socket: Socket,
        backend: Arc<dyn TransitionBackend>,
        peer_verification: PeerVerification,
    ) -> Self {
        Self::with_backend_checked(socket, backend, peer_verification, None)
            .expect("fake socket starts unconnected")
    }

    #[inline]
    pub(crate) fn association(&self) -> AssociationState {
        *self.lock_association()
    }

    #[inline]
    pub(crate) fn is_connected(&self) -> bool {
        self.association().is_connected()
    }

    pub(crate) fn connect_unconnected(&self, peer: SocketAddr) -> Result<(), ManagedSocketError> {
        let mut state = self.lock_association();
        let epoch = match *state {
            AssociationState::Unconnected { epoch } => epoch + 1,
            AssociationState::Connected { .. } => {
                return Err(ManagedSocketError::InvalidTransition {
                    operation: AssociationOperation::Connect,
                    current: *state,
                });
            }
            AssociationState::Poisoned {
                operation, epoch, ..
            } => {
                return Err(ManagedSocketError::Poisoned {
                    operation: AssociationOperation::Connect,
                    poisoned_by: operation,
                    epoch,
                });
            }
        };
        let peer_address = SockAddr::from(peer);
        let transition = self
            .inner
            .backend
            .connect(&self.inner.socket, &peer_address)
            .and_then(|()| self.verify_connected_peer(peer));
        match transition {
            Ok(()) => {
                *state = AssociationState::Connected { peer, epoch };
                Ok(())
            }
            Err(source) => {
                *state = AssociationState::Poisoned {
                    operation: AssociationOperation::Connect,
                    previous_peer: None,
                    epoch,
                };
                Err(ManagedSocketError::Syscall {
                    operation: AssociationOperation::Connect,
                    source,
                })
            }
        }
    }

    pub(crate) fn disconnect_connected(&self) -> Result<(), ManagedSocketError> {
        let mut state = self.lock_association();
        let (previous_peer, epoch) = match *state {
            AssociationState::Connected { peer, epoch } => (peer, epoch + 1),
            AssociationState::Unconnected { .. } => {
                return Err(ManagedSocketError::InvalidTransition {
                    operation: AssociationOperation::Disconnect,
                    current: *state,
                });
            }
            AssociationState::Poisoned {
                operation, epoch, ..
            } => {
                return Err(ManagedSocketError::Poisoned {
                    operation: AssociationOperation::Disconnect,
                    poisoned_by: operation,
                    epoch,
                });
            }
        };
        match self.inner.backend.disconnect(&self.inner.socket) {
            Ok(()) => {
                *state = AssociationState::Unconnected { epoch };
                Ok(())
            }
            Err(source) => {
                *state = AssociationState::Poisoned {
                    operation: AssociationOperation::Disconnect,
                    previous_peer: Some(previous_peer),
                    epoch,
                };
                Err(ManagedSocketError::Syscall {
                    operation: AssociationOperation::Disconnect,
                    source,
                })
            }
        }
    }

    pub(crate) fn reconnect_connected(
        &self,
        new_peer: SocketAddr,
    ) -> Result<(), ManagedSocketError> {
        let mut state = self.lock_association();
        let (previous_peer, epoch) = match *state {
            AssociationState::Connected { peer, epoch } => (peer, epoch + 1),
            AssociationState::Unconnected { .. } => {
                return Err(ManagedSocketError::InvalidTransition {
                    operation: AssociationOperation::Reconnect,
                    current: *state,
                });
            }
            AssociationState::Poisoned {
                operation, epoch, ..
            } => {
                return Err(ManagedSocketError::Poisoned {
                    operation: AssociationOperation::Reconnect,
                    poisoned_by: operation,
                    epoch,
                });
            }
        };
        let transition = self
            .inner
            .backend
            .disconnect(&self.inner.socket)
            .and_then(|()| {
                self.inner
                    .backend
                    .connect(&self.inner.socket, &SockAddr::from(new_peer))
            })
            .and_then(|()| self.verify_connected_peer(new_peer));
        match transition {
            Ok(()) => {
                *state = AssociationState::Connected {
                    peer: new_peer,
                    epoch,
                };
                Ok(())
            }
            Err(source) => {
                *state = AssociationState::Poisoned {
                    operation: AssociationOperation::Reconnect,
                    previous_peer: Some(previous_peer),
                    epoch,
                };
                Err(ManagedSocketError::Syscall {
                    operation: AssociationOperation::Reconnect,
                    source,
                })
            }
        }
    }

    #[inline]
    pub(crate) fn local_addr(&self) -> io::Result<SockAddr> {
        self.inner.socket.local_addr()
    }

    #[inline]
    #[cfg(any(debug_assertions, test))]
    pub(crate) fn peer_addr(&self) -> io::Result<SockAddr> {
        self.inner.socket.peer_addr()
    }

    #[cfg(debug_assertions)]
    pub(crate) fn assert_kernel_association(&self) {
        match self.association() {
            AssociationState::Connected { peer, .. } => {
                if self.inner.peer_verification == PeerVerification::ConnectSuccess {
                    return;
                }
                let kernel_peer = self
                    .peer_addr()
                    .expect("tracked connected socket must have a kernel peer")
                    .as_socket()
                    .expect("managed production sockets must use IP peers");
                debug_assert_eq!(kernel_peer, peer);
            }
            AssociationState::Unconnected { .. } => {
                if self.inner.peer_verification == PeerVerification::RequirePeerAddr {
                    debug_assert!(self.peer_addr().is_err());
                }
            }
            AssociationState::Poisoned { .. } => {}
        }
    }

    pub(crate) fn receive<'a, const CAPACITY: usize>(
        &self,
        syscall: ReceiveSyscall,
        buffer: &'a mut ReceiveBuffer<CAPACITY>,
    ) -> io::Result<ReceivedPacket<'a>> {
        receive::receive(&self.inner.socket, syscall, buffer)
    }

    pub(crate) fn send_packet(
        &self,
        buffers: &[IoSlice<'_>],
        destination: &SockAddr,
    ) -> io::Result<ManagedSendResult> {
        let state = self.lock_association();
        match *state {
            AssociationState::Connected { epoch, .. } => {
                match self
                    .inner
                    .backend
                    .send_connected(&self.inner.socket, buffers)
                {
                    Ok(length) => Ok(ManagedSendResult {
                        length,
                        path: ManagedSendPath::Connected,
                    }),
                    Err(error) if error.raw_os_error() == Some(DEST_ADDR_REQUIRED) => {
                        let mut state = state;
                        *state = AssociationState::Unconnected { epoch: epoch + 1 };
                        let length = self.inner.backend.send_unconnected(
                            &self.inner.socket,
                            buffers,
                            destination,
                        )?;
                        Ok(ManagedSendResult {
                            length,
                            path: ManagedSendPath::RetriedUnconnected,
                        })
                    }
                    Err(error) => Err(error),
                }
            }
            AssociationState::Unconnected { .. } => {
                let length = self.inner.backend.send_unconnected(
                    &self.inner.socket,
                    buffers,
                    destination,
                )?;
                Ok(ManagedSendResult {
                    length,
                    path: ManagedSendPath::Unconnected,
                })
            }
            AssociationState::Poisoned {
                operation, epoch, ..
            } => Err(io::Error::other(format!(
                "send rejected: socket was poisoned by {operation:?} at epoch {epoch}"
            ))),
        }
    }

    pub(crate) fn wait_until_readable(&self, timeout: Duration) -> io::Result<bool> {
        platform::wait_until_readable(&self.inner.socket, timeout)
    }

    fn lock_association(&self) -> MutexGuard<'_, AssociationState> {
        self.inner
            .association
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn verify_connected_peer(&self, requested_peer: SocketAddr) -> io::Result<()> {
        if self.inner.peer_verification == PeerVerification::ConnectSuccess {
            return Ok(());
        }
        let observed_peer = self
            .inner
            .backend
            .peer_addr(&self.inner.socket)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connect succeeded without a kernel peer association",
                )
            })?;
        if observed_peer == requested_peer {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "connect requested peer {requested_peer}, but kernel reports {observed_peer}"
            )))
        }
    }
}

fn peer_absent_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotConnected | io::ErrorKind::InvalidInput | io::ErrorKind::AddrNotAvailable
    )
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::{
        AssociationOperation, AssociationState, ManagedSendPath, ManagedSocket, ManagedSocketError,
        ReceiveBuffer, SockAddr, Socket, TransitionBackend,
    };
    use pkthere_socket_policy::{PeerVerification, ReceiveSyscall};
    use socket2::{Domain, Protocol, Type};
    use std::io::{self, IoSlice};
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::sync::Barrier;
    use std::sync::{Arc, Mutex};
    use std::thread;

    struct FakeState {
        calls: Vec<&'static str>,
        peer: Option<SocketAddr>,
        fail_connect: bool,
        fail_disconnect: bool,
        destination_required_on_send: bool,
        report_peer: bool,
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
            }
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        state: Mutex<FakeState>,
    }

    impl TransitionBackend for FakeBackend {
        fn connect(&self, _socket: &Socket, peer: &SockAddr) -> io::Result<()> {
            let mut state = self.state.lock().expect("fake state");
            state.calls.push("connect");
            if state.fail_connect {
                return Err(io::Error::other("injected connect failure"));
            }
            state.peer = peer.as_socket();
            Ok(())
        }

        fn disconnect(&self, _socket: &Socket) -> io::Result<()> {
            let mut state = self.state.lock().expect("fake state");
            state.calls.push("disconnect");
            if state.fail_disconnect {
                return Err(io::Error::other("injected disconnect failure"));
            }
            state.peer = None;
            Ok(())
        }

        fn peer_addr(&self, _socket: &Socket) -> io::Result<Option<SocketAddr>> {
            let state = self.state.lock().expect("fake state");
            Ok(state.report_peer.then_some(state.peer).flatten())
        }

        fn send_connected(&self, _socket: &Socket, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
            let mut state = self.state.lock().expect("fake state");
            state.calls.push("send");
            if state.destination_required_on_send {
                return Err(io::Error::from_raw_os_error(
                    crate::net::socket_errors::DEST_ADDR_REQUIRED,
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
            self.state.lock().expect("fake state").calls.push("send_to");
            Ok(buffers.iter().map(|buffer| buffer.len()).sum())
        }
    }

    fn fake_socket(backend: Arc<FakeBackend>) -> ManagedSocket {
        fake_socket_with_verification(backend, PeerVerification::RequirePeerAddr)
    }

    fn fake_socket_with_verification(
        backend: Arc<FakeBackend>,
        peer_verification: PeerVerification,
    ) -> ManagedSocket {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .expect("create test socket");
        ManagedSocket::with_backend(socket, backend, peer_verification)
    }

    #[test]
    fn connect_disconnect_and_reconnect_have_authoritative_ordering() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 2002));

        socket.connect_unconnected(first).expect("connect");
        assert_eq!(
            socket.association(),
            AssociationState::Connected {
                peer: first,
                epoch: 1
            }
        );
        socket.reconnect_connected(second).expect("reconnect");
        assert_eq!(
            socket.association(),
            AssociationState::Connected {
                peer: second,
                epoch: 2
            }
        );
        socket.disconnect_connected().expect("disconnect");
        assert_eq!(
            socket.association(),
            AssociationState::Unconnected { epoch: 3 }
        );
        assert_eq!(
            backend.state.lock().expect("fake state").calls,
            ["connect", "disconnect", "connect", "disconnect"]
        );
    }

    #[test]
    fn clones_share_one_association_state() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(backend);
        let clone = socket.clone();
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        socket.connect_unconnected(peer).expect("connect");
        assert_eq!(clone.association(), socket.association());
    }

    #[test]
    fn failed_transition_poisons_socket_and_rejects_later_transitions() {
        let backend = Arc::new(FakeBackend::default());
        backend.state.lock().expect("fake state").fail_connect = true;
        let socket = fake_socket(backend);
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        assert!(matches!(
            socket.connect_unconnected(peer),
            Err(ManagedSocketError::Syscall { .. })
        ));
        assert!(matches!(
            socket.connect_unconnected(peer),
            Err(ManagedSocketError::Poisoned { .. })
        ));
    }

    #[test]
    fn double_connect_returns_typed_error_before_a_second_syscall() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        socket.connect_unconnected(peer).expect("first connect");
        assert!(matches!(
            socket.connect_unconnected(peer),
            Err(ManagedSocketError::InvalidTransition {
                operation: AssociationOperation::Connect,
                ..
            })
        ));
        assert_eq!(backend.state.lock().expect("fake state").calls, ["connect"]);
    }

    #[test]
    fn double_disconnect_returns_typed_error_before_a_second_syscall() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        socket.connect_unconnected(peer).expect("connect");
        socket.disconnect_connected().expect("first disconnect");
        assert!(matches!(
            socket.disconnect_connected(),
            Err(ManagedSocketError::InvalidTransition {
                operation: AssociationOperation::Disconnect,
                ..
            })
        ));
        assert_eq!(
            backend.state.lock().expect("fake state").calls,
            ["connect", "disconnect"]
        );
    }

    #[test]
    fn reconnect_failure_records_one_poison_epoch_and_call_order() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 2002));
        socket.connect_unconnected(first).expect("connect");
        backend.state.lock().expect("fake state").fail_connect = true;

        assert!(matches!(
            socket.reconnect_connected(second),
            Err(ManagedSocketError::Syscall {
                operation: AssociationOperation::Reconnect,
                ..
            })
        ));
        assert_eq!(
            socket.association(),
            AssociationState::Poisoned {
                operation: AssociationOperation::Reconnect,
                previous_peer: Some(first),
                epoch: 2,
            }
        );
        assert_eq!(
            backend.state.lock().expect("fake state").calls,
            ["connect", "disconnect", "connect"]
        );
        assert!(matches!(
            socket.disconnect_connected(),
            Err(ManagedSocketError::Poisoned {
                poisoned_by: AssociationOperation::Reconnect,
                ..
            })
        ));
    }

    #[test]
    fn disconnect_failure_poisons_socket_and_preserves_previous_peer() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        socket.connect_unconnected(peer).expect("connect");
        backend.state.lock().expect("fake state").fail_disconnect = true;

        assert!(matches!(
            socket.disconnect_connected(),
            Err(ManagedSocketError::Syscall {
                operation: AssociationOperation::Disconnect,
                ..
            })
        ));
        assert_eq!(
            socket.association(),
            AssociationState::Poisoned {
                operation: AssociationOperation::Disconnect,
                previous_peer: Some(peer),
                epoch: 2,
            }
        );
        assert!(matches!(
            socket.reconnect_connected(peer),
            Err(ManagedSocketError::Poisoned {
                poisoned_by: AssociationOperation::Disconnect,
                ..
            })
        ));
    }

    #[test]
    fn concurrent_connect_attempts_execute_one_syscall() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let barrier = Arc::new(Barrier::new(3));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        let threads = (0..2)
            .map(|_| {
                let socket = socket.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    socket.connect_unconnected(peer)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().expect("join connect contender"))
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    Err(ManagedSocketError::InvalidTransition {
                        operation: AssociationOperation::Connect,
                        ..
                    })
                ))
                .count(),
            1
        );
        assert_eq!(backend.state.lock().expect("fake state").calls, ["connect"]);
    }

    #[test]
    fn connect_success_verification_accepts_missing_peer_addr_evidence() {
        let backend = Arc::new(FakeBackend::default());
        let socket =
            fake_socket_with_verification(Arc::clone(&backend), PeerVerification::ConnectSuccess);
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        backend.state.lock().expect("fake state").report_peer = false;

        socket.connect_unconnected(peer).expect("opaque connect");
        assert_eq!(
            socket.association(),
            AssociationState::Connected { peer, epoch: 1 }
        );
    }

    #[test]
    fn destination_required_retry_changes_association_before_returning() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        socket.connect_unconnected(peer).expect("connect");
        backend
            .state
            .lock()
            .expect("fake state")
            .destination_required_on_send = true;

        let result = socket
            .send_packet(
                &[IoSlice::new(b"retry")],
                &SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2002))),
            )
            .expect("retry with destination");

        assert_eq!(result.path, ManagedSendPath::RetriedUnconnected);
        assert!(result.association_changed());
        assert_eq!(
            socket.association(),
            AssociationState::Unconnected { epoch: 2 }
        );
        assert_eq!(
            backend.state.lock().expect("fake state").calls,
            ["connect", "send", "send_to"]
        );
    }

    #[test]
    fn delegated_peer_addr_matches_tracked_kernel_association() {
        let receiver =
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP receiver");
        let peer = receiver.local_addr().expect("receiver address");
        let socket =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("create UDP sender");
        socket
            .bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
            .expect("bind UDP sender");
        let managed = ManagedSocket::from_unconnected(socket, PeerVerification::RequirePeerAddr)
            .expect("wrap unconnected sender");
        managed.connect_unconnected(peer).expect("connect sender");
        assert_eq!(
            managed
                .peer_addr()
                .expect("kernel peer")
                .as_socket()
                .expect("IP peer"),
            peer
        );
        assert_eq!(
            managed.association(),
            AssociationState::Connected { peer, epoch: 1 }
        );
    }

    #[test]
    fn checked_constructors_reject_mismatched_kernel_association() {
        let receiver =
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP receiver");
        let peer = receiver.local_addr().expect("receiver address");
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP sender");
        sender.connect(peer).expect("connect sender");

        assert!(matches!(
            ManagedSocket::from_unconnected(
                Socket::from(sender),
                PeerVerification::RequirePeerAddr,
            ),
            Err(ManagedSocketError::UnexpectedInitialAssociation {
                expected_peer: None,
                observed_peer: Some(observed),
            }) if observed == peer
        ));
    }

    #[test]
    fn checked_connected_constructor_requires_the_exact_kernel_peer() {
        let receiver =
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP receiver");
        let peer = receiver.local_addr().expect("receiver address");
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP sender");
        sender.connect(peer).expect("connect sender");

        let managed =
            ManagedSocket::from_connected(Socket::from(sender), peer).expect("adopt connection");
        assert_eq!(
            managed.association(),
            AssociationState::Connected { peer, epoch: 0 }
        );
    }

    #[test]
    fn managed_receive_exposes_only_the_successful_datagram_prefix_and_source() {
        let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind receiver");
        let receiver_address = receiver.local_addr().expect("receiver address");
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
        let sender_address = sender.local_addr().expect("sender address");
        sender
            .send_to(b"managed-receive", receiver_address)
            .expect("send datagram");
        let receiver = ManagedSocket::from_unconnected(
            Socket::from(receiver),
            PeerVerification::RequirePeerAddr,
        )
        .expect("wrap receiver");
        let mut buffer = ReceiveBuffer::<64>::new();

        let packet = receiver
            .receive(ReceiveSyscall::RecvFrom, &mut buffer)
            .expect("receive datagram");
        assert_eq!(packet.bytes(), b"managed-receive");
        assert_eq!(
            packet.source().and_then(SockAddr::as_socket),
            Some(sender_address)
        );
    }

    #[test]
    fn managed_unconnected_send_preserves_zero_length_datagrams() {
        let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind receiver");
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("set receiver timeout");
        let receiver_address = receiver.local_addr().expect("receiver address");
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
        let sender = ManagedSocket::from_unconnected(
            Socket::from(sender),
            PeerVerification::RequirePeerAddr,
        )
        .expect("wrap sender");

        let result = sender
            .send_packet(&[IoSlice::new(&[])], &SockAddr::from(receiver_address))
            .expect("send zero-length datagram");
        assert_eq!(result.path, ManagedSendPath::Unconnected);
        assert_eq!(result.length, 0);
        let mut byte = [0u8; 1];
        assert_eq!(receiver.recv(&mut byte).expect("receive datagram"), 0);
    }
}

#[cfg(all(test, not(miri)))]
#[path = "managed_socket/send_tests.rs"]
mod send_tests;

#[cfg(all(test, not(miri)))]
#[path = "managed_socket/receive_tests.rs"]
mod receive_tests;

#[cfg(all(test, not(miri)))]
#[path = "managed_socket/concurrency_tests.rs"]
mod concurrency_tests;
