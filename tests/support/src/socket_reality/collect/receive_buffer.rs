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
