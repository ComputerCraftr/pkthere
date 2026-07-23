use crate::net::managed_socket::ManagedSocket;
use pkthere_socket_policy::ReceiveSyscall;
use socket2::SockAddr;

use std::io;
use std::mem::MaybeUninit;
use std::time::Duration;

#[inline]
pub(crate) fn recv_packet(
    sock: &ManagedSocket,
    syscall: ReceiveSyscall,
    buf: &mut [MaybeUninit<u8>],
) -> io::Result<(usize, Option<SockAddr>)> {
    match syscall {
        ReceiveSyscall::Recv => sock.recv(buf).map(|len| (len, None)),
        ReceiveSyscall::RecvFrom => sock.recv_from(buf).map(|(len, source)| (len, Some(source))),
    }
}

#[inline]
pub(crate) fn wait_socket_until_readable(
    sock: &ManagedSocket,
    timeout: Duration,
) -> io::Result<bool> {
    sock.wait_until_readable(timeout)
}

#[cfg(test)]
mod tests {
    use super::recv_packet;
    use crate::net::managed_socket::ManagedSocket;
    use crate::recv_buf::RecvBuf;
    use pkthere_socket_policy::ReceiveSyscall;
    use socket2::Socket;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

    #[test]
    fn recv_buf_initialized_exposes_only_requested_length() {
        let mut buf = RecvBuf::<4>::new();
        let recv = buf.recv_buf_mut();
        recv[0].write(b'a');
        recv[1].write(b'b');
        recv[2].write(b'c');
        recv[3].write(b'd');
        assert_eq!(buf.initialized(2), b"ab");
        assert_eq!(buf.initialized(4), b"abcd");
    }

    #[test]
    fn unconnected_recv_returns_source_socket_addr() {
        let recv_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 44444));
        let recv = UdpSocket::bind(recv_addr).expect("bind recv socket");
        let sender = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            55555,
        )))
        .expect("bind sender");
        sender.send_to(b"x", recv_addr).expect("send packet");

        let recv = ManagedSocket::from(Socket::from(recv));
        let mut buf = RecvBuf::<8>::new();
        let (len, source) =
            recv_packet(&recv, ReceiveSyscall::RecvFrom, buf.recv_buf_mut()).expect("recv packet");
        assert_eq!(len, 1);
        let source = source.unwrap().as_socket().expect("source as socket");
        assert_eq!(source, sender.local_addr().expect("sender local"));
    }

    #[test]
    fn connected_recv_uses_kernel_peer_filter_without_source_metadata() {
        let recv = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind recv socket");
        let sender = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind sender");
        let recv_addr = recv.local_addr().expect("recv local address");
        let sender_addr = sender.local_addr().expect("sender local address");
        recv.connect(sender_addr).expect("connect recv socket");
        sender.send_to(b"x", recv_addr).expect("send packet");

        let recv = ManagedSocket::from(Socket::from(recv));
        let mut buf = RecvBuf::<8>::new();
        let (len, source) =
            recv_packet(&recv, ReceiveSyscall::Recv, buf.recv_buf_mut()).expect("recv packet");
        assert_eq!(len, 1);
        assert!(source.is_none());
    }
}
