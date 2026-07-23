use super::{AssociationState, ManagedSocket, ReceiveBuffer};
use pkthere_socket_policy::{PeerVerification, ReceiveSyscall};
use socket2::{SockAddr, Socket};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

const RECEIVE_WORKERS: usize = 3;
const RECEIVE_TEST_WAIT: Duration = Duration::from_secs(1);

fn receiver() -> (ManagedSocket, std::net::SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind receiver");
    socket
        .set_read_timeout(Some(RECEIVE_TEST_WAIT))
        .expect("set receive timeout");
    let address = socket.local_addr().expect("receiver address");
    (
        ManagedSocket::from_unconnected(Socket::from(socket), PeerVerification::RequirePeerAddr)
            .expect("adopt unconnected receiver"),
        address,
    )
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
    let mut buffer = ReceiveBuffer::<1>::new();

    let packet = receiver
        .receive(ReceiveSyscall::RecvFrom, &mut buffer)
        .expect("receive zero-length datagram");

    assert!(packet.bytes().is_empty());
    assert_eq!(
        packet.source().and_then(SockAddr::as_socket),
        Some(sender.local_addr().expect("sender address"))
    );
}

#[test]
fn exact_capacity_and_reuse_never_expose_a_stale_tail() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    let mut buffer = ReceiveBuffer::<8>::new();
    sender
        .send_to(b"12345678", receiver_address)
        .expect("send capacity datagram");
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
    let packet = receiver
        .receive(ReceiveSyscall::Recv, &mut buffer)
        .expect("receive without source");
    assert_eq!(packet.bytes(), b"recv");
    assert!(packet.source().is_none());

    sender
        .send_to(b"recv-from", receiver_address)
        .expect("send recv-from datagram");
    let packet = receiver
        .receive(ReceiveSyscall::RecvFrom, &mut buffer)
        .expect("receive with source");
    assert_eq!(packet.bytes(), b"recv-from");
    assert_eq!(
        packet.source().and_then(SockAddr::as_socket),
        Some(sender_address)
    );
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
                let first = receiver
                    .receive(first_syscall, &mut buffer)
                    .expect("first worker receive");
                result_tx
                    .send((1, worker, first.bytes().to_vec(), first.source().is_some()))
                    .expect("publish first receive");

                second_start.wait();
                let second = receiver
                    .receive(second_syscall, &mut buffer)
                    .expect("second worker receive");
                result_tx
                    .send((
                        2,
                        worker,
                        second.bytes().to_vec(),
                        second.source().is_some(),
                    ))
                    .expect("publish second receive");
            })
        })
        .collect::<Vec<_>>();
    drop(result_tx);

    let first_payloads = [Vec::new(), vec![0xa5; 32], b"first-wave".to_vec()];
    first_start.wait();
    for payload in &first_payloads {
        sender
            .send_to(payload, receiver_address)
            .expect("send first-wave datagram");
    }
    let first_results = (0..RECEIVE_WORKERS)
        .map(|_| {
            result_rx
                .recv_timeout(RECEIVE_TEST_WAIT)
                .expect("receive first-wave worker result")
        })
        .collect::<Vec<_>>();

    let second_payloads = [b"a".to_vec(), b"short".to_vec(), b"after-capacity".to_vec()];
    second_start.wait();
    for payload in &second_payloads {
        sender
            .send_to(payload, receiver_address)
            .expect("send second-wave datagram");
    }
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
