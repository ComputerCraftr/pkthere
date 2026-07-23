use socket2::{SockAddr, Socket};
use std::io;
use std::mem::MaybeUninit;

/// Audited receive storage for direct kernel-evidence probes.
///
/// This is deliberately separate from the production managed-socket receive
/// boundary: reality collectors operate on raw probe sockets, while still
/// ensuring only the prefix initialized by a successful syscall is exposed.
pub(super) struct ProbeReceiveBuffer {
    bytes: Vec<MaybeUninit<u8>>,
}

impl ProbeReceiveBuffer {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: vec![MaybeUninit::uninit(); capacity],
        }
    }

    pub(super) fn recv(&mut self, socket: &Socket) -> io::Result<Vec<u8>> {
        let length = socket.recv(&mut self.bytes)?;
        self.initialized_prefix(length)
    }

    pub(super) fn recv_from(&mut self, socket: &Socket) -> io::Result<(Vec<u8>, SockAddr)> {
        let (length, source) = socket.recv_from(&mut self.bytes)?;
        Ok((self.initialized_prefix(length)?, source))
    }

    fn initialized_prefix(&self, length: usize) -> io::Result<Vec<u8>> {
        if length > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "probe receive length exceeded receive-buffer capacity",
            ));
        }
        // SAFETY: socket2 initializes exactly the first `length` elements on
        // a successful receive. The bounds check prevents reading past them.
        Ok(
            unsafe {
                std::slice::from_raw_parts(self.bytes.as_ptr().cast::<u8>(), length).to_vec()
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ProbeReceiveBuffer;
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
}
