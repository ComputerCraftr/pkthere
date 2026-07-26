use super::receive_buffer::ProbeReceiveBuffer;
use crate::timing::SOCKET_REALITY_RECEIVE_WAIT;
use socket2::Socket;
use std::net::{Ipv4Addr, UdpSocket};

fn receiver() -> (Socket, std::net::SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe receiver");
    socket
        .set_read_timeout(Some(SOCKET_REALITY_RECEIVE_WAIT))
        .expect("set probe timeout");
    let address = socket.local_addr().expect("probe receiver address");
    (Socket::from(socket), address)
}

#[test]
fn probe_buffer_handles_zero_length_and_source_metadata() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe sender");
    sender
        .send_to(&[], receiver_address)
        .expect("send zero-length probe");
    let mut buffer = ProbeReceiveBuffer::with_capacity(1);

    let (bytes, source) = buffer.recv_from(&receiver).expect("receive probe");

    assert!(bytes.is_empty());
    assert_eq!(
        source.as_socket(),
        Some(sender.local_addr().expect("probe sender address"))
    );
}

#[test]
fn probe_buffer_handles_capacity_and_reuse_without_stale_tail() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe sender");
    let mut buffer = ProbeReceiveBuffer::with_capacity(8);
    sender
        .send_to(b"12345678", receiver_address)
        .expect("send capacity probe");
    assert_eq!(
        buffer.recv(&receiver).expect("receive capacity probe"),
        b"12345678"
    );

    sender
        .send_to(b"new", receiver_address)
        .expect("send short probe");
    assert_eq!(buffer.recv(&receiver).expect("reuse probe buffer"), b"new");
}

#[test]
fn probe_buffer_alternates_receive_apis() {
    let (receiver, receiver_address) = receiver();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe sender");
    let mut buffer = ProbeReceiveBuffer::with_capacity(16);
    sender
        .send_to(b"recv", receiver_address)
        .expect("send recv probe");
    assert_eq!(buffer.recv(&receiver).expect("probe recv"), b"recv");

    sender
        .send_to(b"recv-from", receiver_address)
        .expect("send recv-from probe");
    let (bytes, source) = buffer.recv_from(&receiver).expect("probe recv-from");
    assert_eq!(bytes, b"recv-from");
    assert_eq!(
        source.as_socket(),
        Some(sender.local_addr().expect("probe sender address"))
    );
}
