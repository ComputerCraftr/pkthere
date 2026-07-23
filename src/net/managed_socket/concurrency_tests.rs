use super::{
    AssociationState, ManagedSendPath, ManagedSocket, PeerVerification, TransitionBackend,
};
use crate::net::socket_errors::DEST_ADDR_REQUIRED;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{self, IoSlice};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

const CONCURRENCY_WAIT: Duration = Duration::from_secs(1);
const BLOCKED_OBSERVATION_WAIT: Duration = Duration::from_millis(100);

#[derive(Default)]
struct BlockingFallbackState {
    calls: Vec<&'static str>,
    peer: Option<SocketAddr>,
    fallback_entered: bool,
    release_fallback: bool,
}

#[derive(Default)]
struct BlockingFallbackBackend {
    state: Mutex<BlockingFallbackState>,
    changed: Condvar,
}

impl BlockingFallbackBackend {
    fn wait_for_fallback(&self) {
        let state = self.state.lock().expect("fallback state");
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, CONCURRENCY_WAIT, |state| !state.fallback_entered)
            .expect("wait for fallback");
        assert!(
            state.fallback_entered && !timeout.timed_out(),
            "connected sender did not reach the destination-required fallback"
        );
    }

    fn release_fallback(&self) {
        let mut state = self.state.lock().expect("fallback state");
        state.release_fallback = true;
        self.changed.notify_all();
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

    fn send_connected(&self, _socket: &Socket, _buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        self.state
            .lock()
            .expect("fallback state")
            .calls
            .push("send");
        Err(io::Error::from_raw_os_error(DEST_ADDR_REQUIRED))
    }

    fn send_unconnected(
        &self,
        _socket: &Socket,
        buffers: &[IoSlice<'_>],
        _destination: &SockAddr,
    ) -> io::Result<usize> {
        let mut state = self.state.lock().expect("fallback state");
        state.calls.push("send_to");
        if !state.fallback_entered {
            state.fallback_entered = true;
            self.changed.notify_all();
            drop(
                self.changed
                    .wait_while(state, |state| !state.release_fallback)
                    .expect("wait to release fallback"),
            );
        }
        Ok(buffers.iter().map(|buffer| buffer.len()).sum())
    }
}

#[test]
fn concurrent_destination_required_fallback_publishes_one_association_transition() {
    let backend = Arc::new(BlockingFallbackBackend::default());
    let transition_backend: Arc<dyn TransitionBackend> = backend.clone();
    let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("create managed test socket");
    let socket = ManagedSocket::with_backend(
        raw_socket,
        transition_backend,
        PeerVerification::RequirePeerAddr,
    );
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2002)));
    socket
        .connect_unconnected(peer)
        .expect("connect test socket");

    let start = Arc::new(Barrier::new(3));
    let (result_tx, result_rx) = mpsc::channel();
    let senders = (0..2)
        .map(|_| {
            let socket = socket.clone();
            let destination = destination.clone();
            let start = Arc::clone(&start);
            let result_tx = result_tx.clone();
            thread::spawn(move || {
                start.wait();
                let result = socket
                    .send_packet(&[IoSlice::new(b"concurrent")], &destination)
                    .expect("send with managed fallback");
                result_tx.send(result).expect("publish send result");
            })
        })
        .collect::<Vec<_>>();
    drop(result_tx);
    start.wait();
    backend.wait_for_fallback();

    assert!(
        result_rx.recv_timeout(BLOCKED_OBSERVATION_WAIT).is_err(),
        "send_packet returned before the fallback synchronization point"
    );
    let (association_tx, association_rx) = mpsc::channel();
    let observer = {
        let socket = socket.clone();
        thread::spawn(move || {
            association_tx
                .send(socket.association())
                .expect("publish association");
        })
    };
    assert!(
        association_rx
            .recv_timeout(BLOCKED_OBSERVATION_WAIT)
            .is_err(),
        "a clone observed association state while the fallback transition was incomplete"
    );

    backend.release_fallback();
    for sender in senders {
        sender.join().expect("join concurrent sender");
    }
    observer.join().expect("join association observer");

    let results = result_rx.into_iter().collect::<Vec<_>>();
    assert_eq!(results.len(), 2);
    assert_eq!(
        results
            .iter()
            .filter(|result| result.association_changed())
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.path == ManagedSendPath::RetriedUnconnected)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.path == ManagedSendPath::Unconnected)
            .count(),
        1
    );
    assert_eq!(
        association_rx.recv().expect("final association"),
        AssociationState::Unconnected { epoch: 2 }
    );
    assert_eq!(
        socket.association(),
        AssociationState::Unconnected { epoch: 2 }
    );
    assert_eq!(
        backend.state.lock().expect("fallback state").calls,
        ["connect", "send", "send_to", "send_to"]
    );
}
