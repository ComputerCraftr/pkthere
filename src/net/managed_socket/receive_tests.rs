use super::test_support::ProductionIoTestExt;
use super::{
    AssociationState, ManagedReceiver, ManagedSocket, ManagedSocketError, ManagedWakePair,
    ReceiveBuffer, SocketIoLane, WorkerDescriptorCache,
};
use pkthere_socket_policy::{PeerVerification, ReceiveSyscall, SocketRole};
use socket2::Socket;
use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const RECEIVE_WORKERS: usize = 3;
const RECEIVE_TEST_WAIT: Duration = Duration::from_secs(1);

fn receiver() -> (ManagedSocket, std::net::SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind receiver");
    let local_bind = socket.local_addr().expect("receiver address");
    let port = local_bind.port();
    let address = (Ipv4Addr::LOCALHOST, port).into();
    let managed = ManagedSocket::from_unconnected(
        Socket::from(socket),
        PeerVerification::RequirePeerAddr,
        local_bind,
    )
    .expect("adopt unconnected receiver");
    managed
        .configure_worker_io_lanes(RECEIVE_WORKERS)
        .expect("configure receiver worker I/O lanes");
    managed
        .bind_authority_identity(SocketRole::Listener, 0, 1, false)
        .expect("bind receiver authority identity");
    (managed, address)
}

fn wait_for_packet(receiver: &ManagedSocket) {
    let wake = ManagedWakePair::new().expect("create test wake");
    assert_eq!(
        receiver
            .wait_until_readable_or_wake_control(wake.receiver(), RECEIVE_TEST_WAIT)
            .expect("wait for test datagram")
            .flags(),
        (true, false)
    );
}

fn receive_before_deadline<const CAPACITY: usize>(
    receiver: &ManagedSocket,
    lane: SocketIoLane,
    syscall: ReceiveSyscall,
    buffer: &mut ReceiveBuffer<CAPACITY>,
) -> (Vec<u8>, bool) {
    loop {
        match receiver.receive_in_lane(lane, syscall, buffer) {
            Ok(packet) => return (packet.bytes().to_vec(), packet.source().is_some()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => panic!("receive worker syscall failed: {error}"),
        }
    }
}

#[test]
fn connected_recv_has_no_source_metadata() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    receiver
        .connect_unconnected(sender.local_addr().expect("sender address"))
        .expect("connect receiver");
    sender
        .send_to(b"connected", receiver_address)
        .expect("send connected datagram");
    wait_for_packet(&receiver);
    let mut buffer = ReceiveBuffer::<32>::new();

    let packet = receiver
        .receive(ReceiveSyscall::Recv, &mut buffer)
        .expect("connected receive");

    assert_eq!(packet.bytes(), b"connected");
    assert!(packet.source().is_none());
    assert!(matches!(
        receiver.association(),
        AssociationState::Connected { .. }
    ));
}

#[test]
fn zero_length_datagram_is_a_successful_receive() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    sender
        .send_to(&[], receiver_address)
        .expect("send zero-length datagram");
    wait_for_packet(&receiver);
    let mut buffer = ReceiveBuffer::<1>::new();

    let packet = receiver
        .receive(ReceiveSyscall::RecvFrom, &mut buffer)
        .expect("receive zero-length datagram");

    assert!(packet.bytes().is_empty());
    assert_eq!(
        packet.source(),
        Some(sender.local_addr().expect("sender address"))
    );
}

#[test]
fn managed_receive_exposes_only_the_successful_datagram_prefix_and_source() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    let sender_address = sender.local_addr().expect("sender address");
    sender
        .send_to(b"managed-receive", receiver_address)
        .expect("send datagram");
    wait_for_packet(&receiver);
    let mut buffer = ReceiveBuffer::<64>::new();

    let packet = receiver
        .receive(ReceiveSyscall::RecvFrom, &mut buffer)
        .expect("receive datagram");
    assert_eq!(packet.bytes(), b"managed-receive");
    assert_eq!(packet.source(), Some(sender_address));
}

#[test]
fn exact_capacity_and_reuse_never_expose_a_stale_tail() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    let mut buffer = ReceiveBuffer::<8>::new();
    sender
        .send_to(b"12345678", receiver_address)
        .expect("send capacity datagram");
    wait_for_packet(&receiver);
    assert_eq!(
        receiver
            .receive(ReceiveSyscall::RecvFrom, &mut buffer)
            .expect("receive capacity datagram")
            .bytes(),
        b"12345678"
    );

    sender
        .send_to(b"new", receiver_address)
        .expect("send shorter datagram");
    wait_for_packet(&receiver);
    assert_eq!(
        receiver
            .receive(ReceiveSyscall::RecvFrom, &mut buffer)
            .expect("reuse receive buffer")
            .bytes(),
        b"new"
    );
}

#[test]
fn receive_buffer_can_alternate_recv_and_recv_from_without_stale_source() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    let sender_address = sender.local_addr().expect("sender address");
    let mut buffer = ReceiveBuffer::<16>::new();

    sender
        .send_to(b"recv", receiver_address)
        .expect("send recv datagram");
    wait_for_packet(&receiver);
    let packet = receiver
        .receive(ReceiveSyscall::Recv, &mut buffer)
        .expect("receive without source");
    assert_eq!(packet.bytes(), b"recv");
    assert!(packet.source().is_none());

    sender
        .send_to(b"recv-from", receiver_address)
        .expect("send recv-from datagram");
    wait_for_packet(&receiver);
    let packet = receiver
        .receive(ReceiveSyscall::RecvFrom, &mut buffer)
        .expect("receive with source");
    assert_eq!(packet.bytes(), b"recv-from");
    assert_eq!(packet.source(), Some(sender_address));
}

#[test]
fn receive_observation_is_finalized_after_the_successful_syscall() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    sender
        .send_to(b"observed", receiver_address)
        .expect("send observed datagram");
    let managed_receiver = ManagedReceiver::new(&receiver);
    let mut descriptor_cache = WorkerDescriptorCache::for_worker(0);
    managed_receiver
        .reconcile_descriptor_cache(&mut descriptor_cache)
        .expect("reconcile receive descriptor cache");
    let wake = ManagedWakePair::new().expect("create observation wake");
    let readiness = managed_receiver
        .wait_until_readable_or_wake(&mut descriptor_cache, wake.receiver(), RECEIVE_TEST_WAIT)
        .expect("wait for observed datagram");
    let mut buffer = ReceiveBuffer::<16>::new();
    let before_receive = Instant::now();
    let receive_operations =
        crate::authority::operation_count_for_test(crate::authority::OperationId::SocketReceive);

    let (packet, observed_at, _, _) = readiness
        .receive_observed(&mut buffer, ReceiveSyscall::RecvFrom)
        .expect("observed receive")
        .expect("readable datagram");
    let after_receive = Instant::now();

    assert_eq!(
        crate::authority::operation_count_for_test(crate::authority::OperationId::SocketReceive),
        receive_operations + 1,
        "one kernel receive must enter exactly one audited operation scope",
    );
    assert_eq!(packet.bytes(), b"observed");
    assert!(observed_at >= before_receive);
    assert!(observed_at <= after_receive);
}

#[test]
fn association_transition_cannot_change_receive_syscall_evidence_mid_packet() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    receiver
        .connect_unconnected(sender.local_addr().expect("sender address"))
        .expect("connect receiver");
    sender
        .send_to(b"association-stable", receiver_address)
        .expect("send receive fixture");
    wait_for_packet(&receiver);

    let receiving = receiver.clone();
    let (observation_tx, observation_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let receive_thread = thread::spawn(move || {
        let managed_receiver = ManagedReceiver::new(&receiving);
        let mut descriptor_cache = WorkerDescriptorCache::for_worker(0);
        managed_receiver
            .reconcile_descriptor_cache(&mut descriptor_cache)
            .expect("reconcile receive descriptor cache");
        let wake = ManagedWakePair::new().expect("create receive observation wake");
        let readiness = managed_receiver
            .wait_until_readable_or_wake(&mut descriptor_cache, wake.receiver(), RECEIVE_TEST_WAIT)
            .expect("wait with production receive authority");
        assert!(readiness.connected());
        observation_tx.send(()).expect("publish observation");
        release_rx.recv().expect("release receive");
        let mut buffer = ReceiveBuffer::<32>::new();
        readiness
            .receive_observed(&mut buffer, ReceiveSyscall::Recv)
            .expect("observed receive")
            .expect("queued packet")
            .0
            .bytes()
            .to_vec()
    });
    observation_rx
        .recv_timeout(RECEIVE_TEST_WAIT)
        .expect("receive reached observation boundary");

    let transitioning = receiver.clone();
    let (transition_tx, transition_rx) = mpsc::channel();
    let transition_thread = thread::spawn(move || {
        let result = transitioning.disconnect_connected();
        transition_tx.send(result).expect("publish transition");
    });
    assert!(
        transition_rx
            .recv_timeout(Duration::from_millis(10))
            .is_err(),
        "association transition must wait until the selected receive syscall completes"
    );

    release_tx.send(()).expect("release receive");
    assert_eq!(
        receive_thread.join().expect("join receive"),
        b"association-stable"
    );
    let transition = transition_rx
        .recv_timeout(RECEIVE_TEST_WAIT)
        .expect("transition completes after receive");
    match transition {
        Ok(()) => assert!(matches!(
            receiver.association(),
            AssociationState::Unconnected { .. }
        )),
        Err(ManagedSocketError::DisconnectChangedUnexpectedly { .. }) => assert!(matches!(
            receiver.association(),
            AssociationState::Retired { .. }
        )),
        Err(error) => panic!("unexpected disconnect result after receive drained: {error}"),
    }
    transition_thread.join().expect("join transition");
}

#[test]
fn stable_receive_does_not_acquire_the_transition_mutex() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    sender
        .send_to(b"mutex-free-receive", receiver_address)
        .expect("send receive fixture");
    wait_for_packet(&receiver);

    let transition_guard = receiver
        .inner
        .association_state
        .lock()
        .expect("hold transition mutex");
    let receiving = receiver.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let receive_thread = thread::spawn(move || {
        let mut buffer = ReceiveBuffer::<32>::new();
        result_tx
            .send(
                receiving
                    .receive(ReceiveSyscall::RecvFrom, &mut buffer)
                    .map(|packet| packet.bytes().to_vec()),
            )
            .expect("publish receive result");
    });

    let payload = result_rx
        .recv_timeout(RECEIVE_TEST_WAIT)
        .expect("receive must not wait for the transition mutex")
        .expect("receive queued datagram");
    drop(transition_guard);
    receive_thread.join().expect("join receive worker");
    assert_eq!(payload, b"mutex-free-receive");
}

#[test]
fn readiness_poll_retains_descriptor_and_io_lease_until_poll_returns() {
    let (receiver, _) = receiver();
    let wake = Arc::new(ManagedWakePair::new().expect("create readiness wake"));
    let polling_socket = receiver.clone();
    let polling_wake = Arc::clone(&wake);
    let poller = thread::spawn(move || {
        polling_socket
            .wait_until_readable_or_wake_control(polling_wake.receiver(), RECEIVE_TEST_WAIT)
            .expect("poll managed descriptor")
            .flags()
    });
    let poll_deadline = Instant::now() + RECEIVE_TEST_WAIT;
    while !receiver.io_lane_active_for_test(SocketIoLane::Control) {
        assert!(
            Instant::now() < poll_deadline,
            "readiness wait did not acquire its production I/O lane"
        );
        thread::yield_now();
    }

    let transitioning = receiver.clone();
    let (transition_tx, transition_rx) = mpsc::channel();
    let transition = thread::spawn(move || {
        let result = transitioning
            .reserve_replacement()
            .and_then(|reservation| reservation.rollback());
        transition_tx
            .send(result)
            .expect("publish transition result");
    });
    let deadline = Instant::now() + RECEIVE_TEST_WAIT;
    while !receiver.topology_transitioning_for_test() {
        assert!(
            Instant::now() < deadline,
            "topology transition did not close the I/O gate"
        );
        thread::yield_now();
    }
    assert!(
        matches!(transition_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "topology transition completed while readiness poll still owned the descriptor"
    );

    wake.notify().expect("release readiness poll");
    assert_eq!(poller.join().expect("join readiness poll"), (false, true));
    transition_rx
        .recv_timeout(RECEIVE_TEST_WAIT)
        .expect("transition completed after poll")
        .expect("rollback transition");
    transition.join().expect("join transition");
}

#[test]
fn multi_worker_receive_boundary_covers_zero_capacity_reuse_and_mixed_syscalls() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    let first_start = Arc::new(Barrier::new(RECEIVE_WORKERS + 1));
    let second_start = Arc::new(Barrier::new(RECEIVE_WORKERS + 1));
    let (result_tx, result_rx) = mpsc::channel();

    let workers = (0..RECEIVE_WORKERS)
        .map(|worker| {
            let receiver = receiver.clone();
            let first_start = Arc::clone(&first_start);
            let second_start = Arc::clone(&second_start);
            let result_tx = result_tx.clone();
            thread::spawn(move || {
                let lane = match worker {
                    0 => SocketIoLane::Worker(0),
                    1 => SocketIoLane::Worker(1),
                    _ => SocketIoLane::Control,
                };
                let mut buffer = ReceiveBuffer::<32>::new();
                let first_syscall = if worker % 2 == 0 {
                    ReceiveSyscall::Recv
                } else {
                    ReceiveSyscall::RecvFrom
                };
                let second_syscall = if first_syscall == ReceiveSyscall::Recv {
                    ReceiveSyscall::RecvFrom
                } else {
                    ReceiveSyscall::Recv
                };

                first_start.wait();
                let first = receive_before_deadline(&receiver, lane, first_syscall, &mut buffer);
                result_tx
                    .send((1, worker, first.0, first.1))
                    .expect("publish first receive");

                second_start.wait();
                let second = receive_before_deadline(&receiver, lane, second_syscall, &mut buffer);
                result_tx
                    .send((2, worker, second.0, second.1))
                    .expect("publish second receive");
            })
        })
        .collect::<Vec<_>>();
    drop(result_tx);

    let first_payloads = [Vec::new(), vec![0xa5; 32], b"first-wave".to_vec()];
    for payload in &first_payloads {
        sender
            .send_to(payload, receiver_address)
            .expect("send first-wave datagram");
    }
    first_start.wait();
    let first_results = (0..RECEIVE_WORKERS)
        .map(|_| {
            result_rx
                .recv_timeout(RECEIVE_TEST_WAIT)
                .expect("receive first-wave worker result")
        })
        .collect::<Vec<_>>();

    let second_payloads = [b"a".to_vec(), b"short".to_vec(), b"after-capacity".to_vec()];
    for payload in &second_payloads {
        sender
            .send_to(payload, receiver_address)
            .expect("send second-wave datagram");
    }
    second_start.wait();
    let second_results = (0..RECEIVE_WORKERS)
        .map(|_| {
            result_rx
                .recv_timeout(RECEIVE_TEST_WAIT)
                .expect("receive second-wave worker result")
        })
        .collect::<Vec<_>>();

    for worker in workers {
        worker.join().expect("join receive worker");
    }
    assert_receive_wave(&first_results, &first_payloads, 1);
    assert_receive_wave(&second_results, &second_payloads, 2);
    for (wave, worker, _, source_present) in first_results.iter().chain(&second_results) {
        let expected_source = if *wave == 1 {
            worker % 2 == 1
        } else {
            worker % 2 == 0
        };
        assert_eq!(
            *source_present, expected_source,
            "worker {worker} wave {wave} exposed stale or missing source metadata"
        );
    }
}

fn assert_receive_wave(
    results: &[(usize, usize, Vec<u8>, bool)],
    expected_payloads: &[Vec<u8>],
    expected_wave: usize,
) {
    assert!(
        results.iter().all(|(wave, ..)| *wave == expected_wave),
        "received a result from the wrong wave"
    );
    let mut actual = results
        .iter()
        .map(|(_, _, payload, _)| payload.clone())
        .collect::<Vec<_>>();
    let mut expected = expected_payloads.to_vec();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}
