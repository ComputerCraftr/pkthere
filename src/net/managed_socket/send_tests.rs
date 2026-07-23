use super::{AssociationState, ManagedSendPath, ManagedSocket};
use pkthere_socket_policy::PeerVerification;
use socket2::{SockAddr, Socket};
use std::io::IoSlice;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

#[test]
fn connected_send_uses_the_tracked_association_without_destination_selection() {
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind receiver");
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .expect("set receiver timeout");
    let peer = receiver.local_addr().expect("receiver address");
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
    let sender =
        ManagedSocket::from_unconnected(Socket::from(sender), PeerVerification::RequirePeerAddr)
            .expect("wrap sender");
    sender.connect_unconnected(peer).expect("connect sender");

    let result = sender
        .send_packet(
            &[IoSlice::new(b"connected-send")],
            &SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
        )
        .expect("send through tracked peer");
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
