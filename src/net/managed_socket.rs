use socket2::{SockAddr, Socket};
use std::fmt;
use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, SOCKET_ERROR, WSAEINTR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};

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

#[derive(Debug)]
pub(crate) enum ManagedSocketError {
    Syscall {
        operation: AssociationOperation,
        source: io::Error,
    },
    Poisoned {
        operation: AssociationOperation,
        poisoned_by: AssociationOperation,
        epoch: u64,
    },
    StaleObservation {
        observed: AssociationState,
        current: AssociationState,
    },
    KernelStillConnected {
        peer: SocketAddr,
    },
    PeerInspection(io::Error),
}

impl fmt::Display for ManagedSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syscall { operation, source } => {
                write!(
                    formatter,
                    "{operation:?} socket transition failed: {source}"
                )
            }
            Self::Poisoned {
                operation,
                poisoned_by,
                epoch,
            } => write!(
                formatter,
                "{operation:?} rejected: socket was poisoned by {poisoned_by:?} at epoch {epoch}"
            ),
            Self::StaleObservation { observed, current } => write!(
                formatter,
                "destination-required observation is stale: observed {observed:?}, current {current:?}"
            ),
            Self::KernelStillConnected { peer } => {
                write!(formatter, "kernel still reports connected peer {peer}")
            }
            Self::PeerInspection(source) => {
                write!(
                    formatter,
                    "could not inspect kernel peer association: {source}"
                )
            }
        }
    }
}

impl std::error::Error for ManagedSocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syscall { source, .. } | Self::PeerInspection(source) => Some(source),
            Self::Poisoned { .. }
            | Self::StaleObservation { .. }
            | Self::KernelStillConnected { .. } => None,
        }
    }
}

trait TransitionBackend: Send + Sync {
    fn connect(&self, socket: &Socket, peer: &SockAddr) -> io::Result<()>;
    fn disconnect(&self, socket: &Socket) -> io::Result<()>;
    fn peer_addr(&self, socket: &Socket) -> io::Result<Option<SocketAddr>>;
}

struct SystemTransitionBackend;

impl TransitionBackend for SystemTransitionBackend {
    fn connect(&self, socket: &Socket, peer: &SockAddr) -> io::Result<()> {
        socket.connect(peer)
    }

    fn disconnect(&self, socket: &Socket) -> io::Result<()> {
        disconnect_socket(socket)
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
    pub(crate) fn new(socket: Socket) -> Self {
        Self::with_backend(socket, Arc::new(SystemTransitionBackend))
    }

    fn with_backend(socket: Socket, backend: Arc<dyn TransitionBackend>) -> Self {
        Self {
            inner: Arc::new(ManagedSocketInner {
                socket,
                association: Mutex::new(AssociationState::Unconnected { epoch: 0 }),
                backend,
            }),
        }
    }

    #[inline]
    pub(crate) fn association(&self) -> AssociationState {
        *self.lock_association()
    }

    #[inline]
    pub(crate) fn is_connected(&self) -> bool {
        self.association().is_connected()
    }

    #[track_caller]
    pub(crate) fn connect_unconnected(&self, peer: SocketAddr) -> Result<(), ManagedSocketError> {
        let mut state = self.lock_association();
        let epoch = match *state {
            AssociationState::Unconnected { epoch } => epoch + 1,
            AssociationState::Connected { .. } => {
                panic!("attempted to connect an already connected managed socket")
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
            .and_then(|()| {
                self.inner
                    .backend
                    .peer_addr(&self.inner.socket)?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            "connect succeeded without a kernel peer association",
                        )
                    })
            });
        match transition {
            Ok(kernel_peer) => {
                *state = AssociationState::Connected {
                    peer: kernel_peer,
                    epoch,
                };
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

    #[track_caller]
    pub(crate) fn disconnect_connected(&self) -> Result<(), ManagedSocketError> {
        let mut state = self.lock_association();
        let (previous_peer, epoch) = match *state {
            AssociationState::Connected { peer, epoch } => (peer, epoch + 1),
            AssociationState::Unconnected { .. } => {
                panic!("attempted to disconnect an unconnected managed socket")
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

    #[track_caller]
    pub(crate) fn reconnect_connected(
        &self,
        new_peer: SocketAddr,
    ) -> Result<(), ManagedSocketError> {
        let mut state = self.lock_association();
        let (previous_peer, epoch) = match *state {
            AssociationState::Connected { peer, epoch } => (peer, epoch + 1),
            AssociationState::Unconnected { .. } => {
                panic!("attempted to reconnect an unconnected managed socket")
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
            .and_then(|()| {
                self.inner
                    .backend
                    .peer_addr(&self.inner.socket)?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            "reconnect succeeded without a kernel peer association",
                        )
                    })
            });
        match transition {
            Ok(kernel_peer) => {
                *state = AssociationState::Connected {
                    peer: kernel_peer,
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

    pub(crate) fn reconcile_destination_required(
        &self,
        observed_association: AssociationState,
    ) -> Result<bool, ManagedSocketError> {
        let mut state = self.lock_association();
        if *state != observed_association {
            return Err(ManagedSocketError::StaleObservation {
                observed: observed_association,
                current: *state,
            });
        }
        let AssociationState::Connected { epoch, .. } = *state else {
            return Ok(false);
        };
        match self
            .inner
            .backend
            .peer_addr(&self.inner.socket)
            .map_err(ManagedSocketError::PeerInspection)?
        {
            Some(peer) => Err(ManagedSocketError::KernelStillConnected { peer }),
            None => {
                *state = AssociationState::Unconnected { epoch: epoch + 1 };
                Ok(true)
            }
        }
    }

    #[inline]
    pub(crate) fn local_addr(&self) -> io::Result<SockAddr> {
        self.inner.socket.local_addr()
    }

    #[inline]
    pub(crate) fn peer_addr(&self) -> io::Result<SockAddr> {
        self.inner.socket.peer_addr()
    }

    #[cfg(debug_assertions)]
    pub(crate) fn assert_kernel_association(&self) {
        match self.association() {
            AssociationState::Connected { peer, .. } => {
                let kernel_peer = self
                    .peer_addr()
                    .expect("tracked connected socket must have a kernel peer")
                    .as_socket()
                    .expect("managed production sockets must use IP peers");
                debug_assert_eq!(kernel_peer, peer);
            }
            AssociationState::Unconnected { .. } => {
                debug_assert!(self.peer_addr().is_err());
            }
            AssociationState::Poisoned { .. } => {}
        }
    }

    #[inline]
    pub(crate) fn recv(&self, buffer: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        self.inner.socket.recv(buffer)
    }

    #[inline]
    pub(crate) fn recv_from(
        &self,
        buffer: &mut [MaybeUninit<u8>],
    ) -> io::Result<(usize, SockAddr)> {
        self.inner.socket.recv_from(buffer)
    }

    #[inline]
    pub(crate) fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.socket.send(bytes)
    }

    #[inline]
    pub(crate) fn send_to(&self, bytes: &[u8], destination: &SockAddr) -> io::Result<usize> {
        self.inner.socket.send_to(bytes, destination)
    }

    #[inline]
    pub(crate) fn send_vectored(&self, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        self.inner.socket.send_vectored(buffers)
    }

    #[inline]
    pub(crate) fn send_to_vectored(
        &self,
        buffers: &[IoSlice<'_>],
        destination: &SockAddr,
    ) -> io::Result<usize> {
        self.inner.socket.send_to_vectored(buffers, destination)
    }

    #[cfg(unix)]
    pub(crate) fn wait_until_readable(&self, timeout: Duration) -> io::Result<bool> {
        loop {
            let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            let mut poll_descriptor = libc::pollfd {
                fd: self.inner.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut poll_descriptor, 1, timeout_ms) };
            if result > 0 {
                return Ok((poll_descriptor.revents & libc::POLLIN) != 0);
            }
            if result == 0 {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    #[cfg(windows)]
    pub(crate) fn wait_until_readable(&self, timeout: Duration) -> io::Result<bool> {
        loop {
            let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            let mut poll_descriptor = WSAPOLLFD {
                fd: self.inner.socket.as_raw_socket() as usize,
                events: POLLRDNORM,
                revents: 0,
            };
            let result = unsafe { WSAPoll(&mut poll_descriptor, 1, timeout_ms) };
            if result > 0 {
                return Ok((poll_descriptor.revents & POLLRDNORM) != 0);
            }
            if result == 0 {
                return Ok(false);
            }
            let error = unsafe { WSAGetLastError() };
            if error == WSAEINTR {
                continue;
            }
            if result == SOCKET_ERROR {
                return Err(io::Error::from_raw_os_error(error));
            }
            return Err(io::Error::other("unexpected WSAPoll return value"));
        }
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn wait_until_readable(&self, _timeout: Duration) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "socket readiness waiting is not implemented on this platform",
        ))
    }

    fn lock_association(&self) -> MutexGuard<'_, AssociationState> {
        self.inner
            .association
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl From<Socket> for ManagedSocket {
    fn from(socket: Socket) -> Self {
        Self::new(socket)
    }
}

fn peer_absent_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotConnected | io::ErrorKind::InvalidInput | io::ErrorKind::AddrNotAvailable
    )
}

/// Disconnect-before-reconnect is a pkthere portability invariant.
#[cfg(unix)]
fn disconnect_socket(socket: &Socket) -> io::Result<()> {
    let file_descriptor = socket.as_raw_fd();

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    let address = libc::sockaddr {
        sa_len: std::mem::size_of::<libc::sockaddr>() as u8,
        sa_family: libc::AF_UNSPEC as libc::sa_family_t,
        sa_data: [0; 14],
    };

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    let address = libc::sockaddr {
        sa_family: libc::AF_UNSPEC as libc::sa_family_t,
        sa_data: [0; 14],
    };

    let result = unsafe {
        libc::connect(
            file_descriptor,
            &address as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    if error.raw_os_error() == Some(libc::EAFNOSUPPORT) {
        return Ok(());
    }
    Err(error)
}

#[cfg(windows)]
fn disconnect_socket(socket: &Socket) -> io::Result<()> {
    let local = socket.local_addr()?;
    let unspecified = match local.as_socket() {
        Some(SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    socket.connect(&SockAddr::from(unspecified))
}

#[cfg(all(not(unix), not(windows)))]
fn disconnect_socket(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed socket disconnect is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        AssociationOperation, AssociationState, ManagedSocket, ManagedSocketError, SockAddr,
        Socket, TransitionBackend,
    };
    use socket2::{Domain, Protocol, Type};
    use std::io;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::panic::AssertUnwindSafe;
    use std::sync::Barrier;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Default)]
    struct FakeState {
        calls: Vec<&'static str>,
        peer: Option<SocketAddr>,
        fail_connect: bool,
        fail_disconnect: bool,
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
            Ok(self.state.lock().expect("fake state").peer)
        }
    }

    fn fake_socket(backend: Arc<FakeBackend>) -> ManagedSocket {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .expect("create test socket");
        ManagedSocket::with_backend(socket, backend)
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
    #[should_panic(expected = "already connected")]
    fn double_connect_panics_before_a_second_syscall() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        socket.connect_unconnected(peer).expect("first connect");
        socket
            .connect_unconnected(peer)
            .expect("second connect must panic");
    }

    #[test]
    #[should_panic(expected = "unconnected managed socket")]
    fn double_disconnect_panics_before_a_second_syscall() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(backend);
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        socket.connect_unconnected(peer).expect("connect");
        socket.disconnect_connected().expect("first disconnect");
        socket
            .disconnect_connected()
            .expect("second disconnect must panic");
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
                    std::panic::catch_unwind(AssertUnwindSafe(|| socket.connect_unconnected(peer)))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().expect("join connect contender"))
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(backend.state.lock().expect("fake state").calls, ["connect"]);
    }

    #[test]
    fn destination_required_reconciliation_requires_absent_kernel_peer() {
        let backend = Arc::new(FakeBackend::default());
        let socket = fake_socket(Arc::clone(&backend));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
        socket.connect_unconnected(peer).expect("connect");
        let observed = socket.association();
        assert!(matches!(
            socket.reconcile_destination_required(observed),
            Err(ManagedSocketError::KernelStillConnected { .. })
        ));
        backend.state.lock().expect("fake state").peer = None;
        assert!(
            socket
                .reconcile_destination_required(observed)
                .expect("reconcile absent peer")
        );
        assert_eq!(
            socket.association(),
            AssociationState::Unconnected { epoch: 2 }
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
        let managed = ManagedSocket::new(socket);
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
}
