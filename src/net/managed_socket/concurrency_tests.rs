use super::test_support::ProductionIoTestExt;
use super::{
    AssociationState, ManagedSendPath, ManagedSocket, PeerVerification, ReceiveBuffer,
    ReceiveSyscall, SocketIoLane, TransitionBackend,
};
use crate::net::managed_socket::DEST_ADDR_REQUIRED;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{self, IoSlice};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

const CONCURRENCY_WAIT: Duration = Duration::from_secs(1);
const BLOCKED_OBSERVATION_WAIT: Duration = Duration::from_millis(100);
const SEND_FIXTURE: &[u8] = b"lock-free-send";

fn assert_transition_lock_becomes_available(socket: &ManagedSocket, context: &str) {
    let deadline = std::time::Instant::now() + BLOCKED_OBSERVATION_WAIT;
    while !socket.transition_lock_available_for_test() {
        assert!(
            std::time::Instant::now() < deadline,
            "{context}: transition mutex remained locked while I/O drained"
        );
        thread::yield_now();
    }
}

#[derive(Default)]
struct ParallelSendState {
    peer: Option<SocketAddr>,
    active_senders: usize,
    maximum_active_senders: usize,
    release_senders: bool,
}

#[derive(Default)]
struct ParallelSendBackend {
    state: Mutex<ParallelSendState>,
    changed: Condvar,
}

impl ParallelSendBackend {
    fn wait_for_active_senders(&self, count: usize) {
        let state = self.state.lock().expect("parallel state");
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, CONCURRENCY_WAIT, |state| {
                state.maximum_active_senders < count
            })
            .expect("wait for active senders");
        assert!(
            state.maximum_active_senders >= count && !timeout.timed_out(),
            "expected {count} active send syscall(s)"
        );
    }

    fn wait_for_parallel_senders(&self) {
        self.wait_for_active_senders(2);
    }

    fn release_senders(&self) {
        let mut state = self.state.lock().expect("parallel state");
        state.release_senders = true;
        self.changed.notify_all();
    }

    fn send(&self, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut state = self.state.lock().expect("parallel state");
        state.active_senders += 1;
        state.maximum_active_senders = state.maximum_active_senders.max(state.active_senders);
        self.changed.notify_all();
        let mut state = self
            .changed
            .wait_while(state, |state| !state.release_senders)
            .expect("wait to release parallel senders");
        state.active_senders -= 1;
        self.changed.notify_all();
        Ok(buffers.iter().map(|buffer| buffer.len()).sum())
    }
}

impl TransitionBackend for ParallelSendBackend {
    fn connect(&self, _socket: &Socket, peer: &SockAddr) -> io::Result<()> {
        self.state.lock().expect("parallel state").peer = peer.as_socket();
        Ok(())
    }

    fn disconnect(&self, _socket: &Socket) -> io::Result<()> {
        self.state.lock().expect("parallel state").peer = None;
        Ok(())
    }

    fn peer_addr(&self, _socket: &Socket) -> io::Result<Option<SocketAddr>> {
        Ok(self.state.lock().expect("parallel state").peer)
    }

    fn local_addr(&self, _socket: &Socket) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 40_001)))
    }

    fn send_connected(&self, _socket: &Socket, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        self.send(buffers)
    }

    fn send_unconnected(
        &self,
        _socket: &Socket,
        buffers: &[IoSlice<'_>],
        _destination: &SockAddr,
    ) -> io::Result<usize> {
        self.send(buffers)
    }
}

#[derive(Default)]
struct BlockingFallbackState {
    calls: Vec<&'static str>,
    peer: Option<SocketAddr>,
    connected_send_attempts: usize,
}

#[derive(Default)]
struct BlockingFallbackBackend {
    state: Mutex<BlockingFallbackState>,
    changed: Condvar,
}

#[derive(Default)]
struct BlockingTransitionState {
    peer: Option<SocketAddr>,
    entered: bool,
    release: bool,
}

#[derive(Default)]
struct BlockingTransitionBackend {
    state: Mutex<BlockingTransitionState>,
    changed: Condvar,
}

impl BlockingTransitionBackend {
    fn arm(&self) {
        let mut state = self.state.lock().expect("transition state");
        state.entered = false;
        state.release = false;
    }

    fn allow(&self) {
        let mut state = self.state.lock().expect("transition state");
        state.release = true;
        self.changed.notify_all();
    }

    fn wait_until_entered(&self) {
        let state = self.state.lock().expect("transition state");
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, CONCURRENCY_WAIT, |state| !state.entered)
            .expect("wait for transition backend");
        assert!(state.entered && !timeout.timed_out());
    }

    fn block(&self) {
        let mut state = self.state.lock().expect("transition state");
        state.entered = true;
        self.changed.notify_all();
        drop(
            self.changed
                .wait_while(state, |state| !state.release)
                .expect("release transition backend"),
        );
    }
}

impl TransitionBackend for BlockingTransitionBackend {
    fn connect(&self, _socket: &Socket, peer: &SockAddr) -> io::Result<()> {
        self.block();
        self.state.lock().expect("transition state").peer = peer.as_socket();
        Ok(())
    }

    fn disconnect(&self, _socket: &Socket) -> io::Result<()> {
        self.block();
        self.state.lock().expect("transition state").peer = None;
        Ok(())
    }

    fn peer_addr(&self, _socket: &Socket) -> io::Result<Option<SocketAddr>> {
        Ok(self.state.lock().expect("transition state").peer)
    }

    fn local_addr(&self, _socket: &Socket) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 40_002)))
    }
}

impl TransitionBackend for BlockingFallbackBackend {
    fn connect(&self, _socket: &Socket, peer: &SockAddr) -> io::Result<()> {
        let mut state = self.state.lock().expect("fallback state");
        state.calls.push("connect");
        state.peer = peer.as_socket();
        Ok(())
    }

    fn disconnect(&self, _socket: &Socket) -> io::Result<()> {
        let mut state = self.state.lock().expect("fallback state");
        state.calls.push("disconnect");
        state.peer = None;
        Ok(())
    }

    fn peer_addr(&self, _socket: &Socket) -> io::Result<Option<SocketAddr>> {
        Ok(self.state.lock().expect("fallback state").peer)
    }

    fn local_addr(&self, _socket: &Socket) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 40_003)))
    }

    fn send_connected(&self, _socket: &Socket, _buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut state = self.state.lock().expect("fallback state");
        state.calls.push("send");
        state.connected_send_attempts += 1;
        self.changed.notify_all();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, CONCURRENCY_WAIT, |state| {
                state.connected_send_attempts < 2
            })
            .expect("wait for both connected send attempts");
        assert!(
            state.connected_send_attempts == 2 && !timeout.timed_out(),
            "both senders must observe the connected association before fallback"
        );
        Err(io::Error::from_raw_os_error(DEST_ADDR_REQUIRED))
    }
}

#[test]
fn concurrent_destination_required_sends_return_stale_without_inline_transition() {
    let backend = Arc::new(BlockingFallbackBackend::default());
    let transition_backend: Arc<dyn TransitionBackend> = backend.clone();
    let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("create managed test socket");
    let socket = ManagedSocket::with_backend(
        raw_socket,
        transition_backend,
        PeerVerification::RequirePeerAddr,
        SocketAddr::from(([127, 0, 0, 1], 40_003)),
    );
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2002)));
    socket
        .connect_unconnected(peer)
        .expect("connect test socket");

    let start = Arc::new(Barrier::new(3));
    let (result_tx, result_rx) = mpsc::channel();
    let senders = (0..2)
        .map(|index| {
            let socket = socket.clone();
            let destination = destination.clone();
            let start = Arc::clone(&start);
            let result_tx = result_tx.clone();
            thread::spawn(move || {
                let mut cache = super::WorkerDescriptorCache::for_worker(index);
                cache
                    .reconcile(&socket)
                    .expect("reconcile stale-send descriptor cache");
                start.wait();
                let result = socket.acquire_send_lease(&mut cache).and_then(|lease| {
                    lease.send_packet(&[IoSlice::new(b"concurrent")], &destination)
                });
                result_tx.send(result).expect("publish send result");
            })
        })
        .collect::<Vec<_>>();
    drop(result_tx);
    start.wait();
    for sender in senders {
        sender.join().expect("join concurrent sender");
    }
    let results = [
        result_rx
            .recv_timeout(CONCURRENCY_WAIT)
            .expect("first stale result"),
        result_rx
            .recv_timeout(CONCURRENCY_WAIT)
            .expect("second stale result"),
    ];
    assert!(results.iter().all(|result| {
        result.as_ref().is_err_and(|error| {
            super::AssociationStale::from_io(error).is_some_and(|stale| stale.expected_epoch() == 1)
        })
    }));
    assert_eq!(
        socket.association(),
        AssociationState::Connected { peer, epoch: 1 }
    );
    assert_eq!(
        backend.state.lock().expect("fallback state").calls,
        ["connect", "send", "send"]
    );
}

#[test]
fn receive_mutation_authority_blocks_transition_and_rejects_stale_epoch() {
    let backend = Arc::new(ParallelSendBackend::default());
    let transition_backend: Arc<dyn TransitionBackend> = backend.clone();
    let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("create managed test socket");
    let socket = ManagedSocket::with_backend(
        raw_socket,
        transition_backend,
        PeerVerification::RequirePeerAddr,
        SocketAddr::from(([127, 0, 0, 1], 40_001)),
    );
    let stale_epoch = socket.topology_epoch();
    let authority = socket
        .acquire_topology_authority(stale_epoch, super::SocketIoLane::Control)
        .expect("acquire receive mutation authority");
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 2112));
    let transitioning = socket.clone();
    let transition = thread::spawn(move || {
        transitioning
            .connect_unconnected(peer)
            .expect("connect after receive mutation completes");
    });

    let observe_deadline = std::time::Instant::now() + BLOCKED_OBSERVATION_WAIT;
    while !socket.topology_transitioning_for_test() {
        assert!(
            std::time::Instant::now() < observe_deadline,
            "transition did not close the topology gate"
        );
        thread::yield_now();
    }
    assert_transition_lock_becomes_available(
        &socket,
        "receive mutation authority blocked the topology transition",
    );
    assert_eq!(
        backend.state.lock().expect("parallel state").peer,
        None,
        "transition syscall must wait for receive mutation authority"
    );
    drop(authority);
    transition.join().expect("transition thread");

    assert_eq!(
        backend.state.lock().expect("parallel state").peer,
        Some(peer)
    );
    let error = match socket.acquire_topology_authority(stale_epoch, super::SocketIoLane::Control) {
        Ok(_) => panic!("old receive authority survived topology publication"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn transition_backend_syscalls_do_not_hold_the_association_mutex() {
    let backend = Arc::new(BlockingTransitionBackend::default());
    let transition_backend: Arc<dyn TransitionBackend> = backend.clone();
    let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("create managed test socket");
    let socket = ManagedSocket::with_backend(
        raw_socket,
        transition_backend,
        PeerVerification::RequirePeerAddr,
        SocketAddr::from(([127, 0, 0, 1], 40_002)),
    );
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));

    backend.arm();
    let connecting = socket.clone();
    let connect = thread::spawn(move || connecting.connect_unconnected(peer));
    backend.wait_until_entered();
    assert!(
        socket.transition_lock_available_for_test(),
        "connect backend syscall must not retain the association mutex"
    );
    backend.allow();
    connect
        .join()
        .expect("join connect transition")
        .expect("connect transition");

    backend.arm();
    let disconnecting = socket.clone();
    let disconnect = thread::spawn(move || disconnecting.disconnect_connected());
    backend.wait_until_entered();
    assert!(
        socket.transition_lock_available_for_test(),
        "disconnect backend syscall must not retain the association mutex"
    );
    backend.allow();
    disconnect
        .join()
        .expect("join disconnect transition")
        .expect("disconnect transition");
}

#[test]
fn connected_multi_worker_sends_share_state_without_serializing_syscalls() {
    let backend = Arc::new(ParallelSendBackend::default());
    let transition_backend: Arc<dyn TransitionBackend> = backend.clone();
    let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("create managed test socket");
    let socket = ManagedSocket::with_backend(
        raw_socket,
        transition_backend,
        PeerVerification::RequirePeerAddr,
        SocketAddr::from(([127, 0, 0, 1], 40_001)),
    );
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    socket
        .connect_unconnected(peer)
        .expect("connect managed socket");
    let destination = Arc::new(SockAddr::from(peer));
    let start = Arc::new(Barrier::new(3));

    let workers = (0..2)
        .map(|index| {
            let socket = socket.clone();
            let destination = Arc::clone(&destination);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                let mut cache = super::WorkerDescriptorCache::for_worker(index);
                cache.reconcile(&socket)?;
                start.wait();
                socket
                    .acquire_send_lease(&mut cache)?
                    .send_packet(&[IoSlice::new(b"x")], &destination)
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    backend.wait_for_parallel_senders();
    assert!(
        socket.transition_lock_available_for_test(),
        "send syscalls must not hold the transition mutex"
    );

    let transitioning = socket.clone();
    let (transition_tx, transition_rx) = mpsc::channel();
    let transition = thread::spawn(move || {
        transition_tx
            .send(transitioning.disconnect_connected())
            .expect("publish disconnect result");
    });
    let transition_deadline = std::time::Instant::now() + CONCURRENCY_WAIT;
    while !socket.topology_transitioning_for_test() {
        assert!(
            std::time::Instant::now() < transition_deadline,
            "disconnect did not publish its transition gate"
        );
        thread::yield_now();
    }
    let rejected = socket
        .send_packet(&[IoSlice::new(b"closed-gate")], &destination)
        .expect_err("topology closure must reject new send leases");
    assert_eq!(rejected.kind(), io::ErrorKind::WouldBlock);
    assert!(
        transition_rx
            .recv_timeout(BLOCKED_OBSERVATION_WAIT)
            .is_err(),
        "disconnect must drain active sends before changing the kernel association"
    );

    backend.release_senders();
    for worker in workers {
        worker
            .join()
            .expect("join sender")
            .expect("parallel connected send");
    }
    transition_rx
        .recv_timeout(CONCURRENCY_WAIT)
        .expect("disconnect completes after sends drain")
        .expect("disconnect connected socket");
    transition.join().expect("join disconnect");

    assert_eq!(
        backend
            .state
            .lock()
            .expect("parallel state")
            .maximum_active_senders,
        2,
        "association tracking must permit concurrent connected send syscalls"
    );
    assert_eq!(
        socket.association(),
        AssociationState::Unconnected { epoch: 2 }
    );
}

#[test]
fn receive_progresses_while_the_opposite_lane_send_syscall_is_blocked() {
    let backend = Arc::new(ParallelSendBackend::default());
    let transition_backend: Arc<dyn TransitionBackend> = backend.clone();
    let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("create managed test socket");
    raw_socket
        .bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
        .expect("bind managed receive socket");
    raw_socket
        .set_nonblocking(true)
        .expect("make receive socket nonblocking");
    let receive_address = raw_socket
        .local_addr()
        .expect("managed local address")
        .as_socket()
        .expect("INET managed address");
    let socket = ManagedSocket::with_backend(
        raw_socket,
        transition_backend,
        PeerVerification::RequirePeerAddr,
        receive_address,
    );
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 20_002)));
    let blocked_socket = socket.clone();
    let blocked_destination = destination.clone();
    let blocked_send = thread::spawn(move || {
        let mut cache = super::WorkerDescriptorCache::for_worker(0);
        cache.reconcile(&blocked_socket)?;
        blocked_socket
            .acquire_send_lease(&mut cache)?
            .send_packet(&[IoSlice::new(b"blocked-send")], &blocked_destination)
    });
    backend.wait_for_active_senders(1);

    let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind independent receive fixture sender");
    sender
        .send_to(b"receive-progress", receive_address)
        .expect("queue packet while send syscall is blocked");
    let readiness_deadline = std::time::Instant::now() + CONCURRENCY_WAIT;
    let mut buffer = ReceiveBuffer::<64>::new();
    let received = loop {
        match socket.receive_in_lane(
            SocketIoLane::Worker(1),
            ReceiveSyscall::RecvFrom,
            &mut buffer,
        ) {
            Ok(packet) => break packet,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < readiness_deadline =>
            {
                thread::yield_now();
            }
            Err(error) => panic!("receive while opposite send is blocked: {error}"),
        }
    };
    assert_eq!(received.bytes(), b"receive-progress");

    backend.release_senders();
    blocked_send
        .join()
        .expect("join blocked sender")
        .expect("complete blocked send");
}

#[test]
fn unconnected_multi_worker_sends_do_not_serialize_syscalls() {
    let backend = Arc::new(ParallelSendBackend::default());
    let transition_backend: Arc<dyn TransitionBackend> = backend.clone();
    let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("create managed test socket");
    let socket = ManagedSocket::with_backend(
        raw_socket,
        transition_backend,
        PeerVerification::RequirePeerAddr,
        SocketAddr::from(([127, 0, 0, 1], 40_001)),
    );
    let destination = Arc::new(SockAddr::from(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        1001,
    ))));
    let start = Arc::new(Barrier::new(3));

    let workers = (0..2)
        .map(|index| {
            let socket = socket.clone();
            let destination = Arc::clone(&destination);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                let mut cache = super::WorkerDescriptorCache::for_worker(index);
                cache.reconcile(&socket)?;
                start.wait();
                socket
                    .acquire_send_lease(&mut cache)?
                    .send_packet(&[IoSlice::new(SEND_FIXTURE)], &destination)
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    backend.wait_for_parallel_senders();
    assert!(
        socket.transition_lock_available_for_test(),
        "unconnected send syscalls must not hold the transition mutex"
    );

    backend.release_senders();
    for worker in workers {
        let result = worker
            .join()
            .expect("join sender")
            .expect("parallel unconnected send");
        assert_eq!(result.path, ManagedSendPath::Unconnected);
        assert_eq!(result.length, SEND_FIXTURE.len());
    }
    assert_eq!(
        backend
            .state
            .lock()
            .expect("parallel state")
            .maximum_active_senders,
        2
    );
}

#[test]
fn stable_send_branches_do_not_acquire_the_transition_mutex() {
    let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP receiver");
    let destination = receiver.local_addr().expect("receiver address");
    let destination_sa = SockAddr::from(destination);

    let connected_socket =
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind connected sender");
    connected_socket
        .connect(destination)
        .expect("connect UDP sender");
    let connected_local = connected_socket
        .local_addr()
        .expect("connected sender address");
    let connected =
        ManagedSocket::from_connected(Socket::from(connected_socket), destination, connected_local)
            .expect("adopt connected sender");
    assert_send_completes_while_transition_mutex_is_held(
        connected,
        destination_sa.clone(),
        ManagedSendPath::Connected,
    );

    let unconnected_socket =
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind unconnected sender");
    let unconnected_local = unconnected_socket
        .local_addr()
        .expect("unconnected sender address");
    let unconnected = ManagedSocket::from_unconnected(
        Socket::from(unconnected_socket),
        PeerVerification::RequirePeerAddr,
        unconnected_local,
    )
    .expect("adopt unconnected sender");
    assert_send_completes_while_transition_mutex_is_held(
        unconnected,
        destination_sa,
        ManagedSendPath::Unconnected,
    );
}

fn assert_send_completes_while_transition_mutex_is_held(
    socket: ManagedSocket,
    destination: SockAddr,
    expected_path: ManagedSendPath,
) {
    let transition_guard = socket
        .inner
        .association_state
        .lock()
        .expect("hold transition mutex");
    let sending = socket.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let sender = thread::spawn(move || {
        result_tx
            .send(sending.send_packet(&[IoSlice::new(SEND_FIXTURE)], &destination))
            .expect("publish send result");
    });
    let result = result_rx.recv_timeout(CONCURRENCY_WAIT);
    drop(transition_guard);
    sender.join().expect("join lock-free sender");

    let result = result
        .expect("stable send path must not wait for the transition mutex")
        .expect("send while transition mutex is held");
    assert_eq!(result.path, expected_path);
    assert_eq!(result.length, SEND_FIXTURE.len());
}
