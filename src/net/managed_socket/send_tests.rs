use super::test_support::ProductionIoTestExt;
use super::{AssociationState, ManagedSendPath, ManagedSocket};
use pkthere_socket_policy::PeerVerification;
use socket2::{SockAddr, Socket};
use std::io::IoSlice;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const SEND_TEST_RECEIVE_WAIT: Duration = Duration::from_secs(1);

#[test]
fn connected_send_uses_the_tracked_association_without_destination_selection() {
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind receiver");
    receiver
        .set_read_timeout(Some(SEND_TEST_RECEIVE_WAIT))
        .expect("set receiver timeout");
    let peer = receiver.local_addr().expect("receiver address");
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    let sender_local = sender.local_addr().expect("sender address");
    let sender = ManagedSocket::from_unconnected(
        Socket::from(sender),
        PeerVerification::RequirePeerAddr,
        sender_local,
    )
    .expect("wrap sender");
    sender.connect_unconnected(peer).expect("connect sender");
    let send_operations =
        crate::authority::operation_count_for_test(crate::authority::OperationId::SocketSend);

    let result = sender
        .send_packet(
            &[IoSlice::new(b"connected-send")],
            &SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
        )
        .expect("send through tracked peer");
    assert_eq!(
        crate::authority::operation_count_for_test(crate::authority::OperationId::SocketSend),
        send_operations + 1,
        "one kernel send must enter exactly one audited operation scope",
    );
    assert_eq!(result.path, ManagedSendPath::Connected);
    assert_eq!(result.length, b"connected-send".len());
    assert!(matches!(
        sender.association(),
        AssociationState::Connected {
            peer: connected_peer,
            ..
        } if connected_peer == peer
    ));
    let mut bytes = [0u8; 32];
    let length = receiver.recv(&mut bytes).expect("receive connected send");
    assert_eq!(&bytes[..length], b"connected-send");
}

#[test]
fn unconnected_send_preserves_zero_length_datagrams() {
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind receiver");
    receiver
        .set_read_timeout(Some(SEND_TEST_RECEIVE_WAIT))
        .expect("set receiver timeout");
    let receiver_address = receiver.local_addr().expect("receiver address");
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    let sender_local = sender.local_addr().expect("sender address");
    let sender = ManagedSocket::from_unconnected(
        Socket::from(sender),
        PeerVerification::RequirePeerAddr,
        sender_local,
    )
    .expect("wrap sender");
    let send_operations =
        crate::authority::operation_count_for_test(crate::authority::OperationId::SocketSend);

    let result = sender
        .send_packet(&[IoSlice::new(&[])], &SockAddr::from(receiver_address))
        .expect("send zero-length datagram");
    assert_eq!(
        crate::authority::operation_count_for_test(crate::authority::OperationId::SocketSend),
        send_operations + 1,
        "one kernel send-to must enter exactly one audited operation scope",
    );
    assert_eq!(result.path, ManagedSendPath::Unconnected);
    assert_eq!(result.length, 0);
    let mut byte = [0u8; 1];
    assert_eq!(receiver.recv(&mut byte).expect("receive datagram"), 0);
}
