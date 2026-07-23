use pkthere_socket_policy::ReceiveSyscall;
use socket2::{SockAddr, Socket};
use std::io;
use std::mem::MaybeUninit;

/// Per-worker storage for one receive operation.
pub(crate) struct ReceiveBuffer<const CAPACITY: usize> {
    bytes: [MaybeUninit<u8>; CAPACITY],
}

impl<const CAPACITY: usize> ReceiveBuffer<CAPACITY> {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [MaybeUninit::uninit(); CAPACITY],
        }
    }

    fn initialized_prefix(&self, length: usize) -> io::Result<&[u8]> {
        if length > CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socket receive length exceeded receive-buffer capacity",
            ));
        }
        // SAFETY: callers may expose only the prefix initialized by a
        // successful receive. The bounds check prevents exposing bytes beyond
        // the backing allocation.
        Ok(unsafe { std::slice::from_raw_parts(self.bytes.as_ptr().cast::<u8>(), length) })
    }
}

pub(crate) struct ReceivedPacket<'a> {
    bytes: &'a [u8],
    source: Option<SockAddr>,
}

impl<'a> ReceivedPacket<'a> {
    #[inline]
    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[inline]
    pub(crate) fn source(&self) -> Option<&SockAddr> {
        self.source.as_ref()
    }
}

pub(super) fn receive<'a, const CAPACITY: usize>(
    socket: &Socket,
    syscall: ReceiveSyscall,
    buffer: &'a mut ReceiveBuffer<CAPACITY>,
) -> io::Result<ReceivedPacket<'a>> {
    let (length, source) = match syscall {
        ReceiveSyscall::Recv => (socket.recv(&mut buffer.bytes)?, None),
        ReceiveSyscall::RecvFrom => {
            let (length, source) = socket.recv_from(&mut buffer.bytes)?;
            (length, Some(source))
        }
    };
    // socket2's successful recv/recv_from contract initializes exactly the
    // first `length` bytes.
    let bytes = buffer.initialized_prefix(length)?;
    Ok(ReceivedPacket { bytes, source })
}

#[cfg(test)]
mod tests {
    use super::ReceiveBuffer;
    use std::io::ErrorKind;

    #[test]
    fn initialized_receive_prefix_handles_zero_capacity_and_reuse() {
        let mut buffer = ReceiveBuffer::<8>::new();
        assert!(
            buffer
                .initialized_prefix(0)
                .expect("zero prefix")
                .is_empty()
        );

        for (slot, byte) in buffer.bytes.iter_mut().zip(*b"12345678") {
            slot.write(byte);
        }
        assert_eq!(
            buffer.initialized_prefix(8).expect("capacity prefix"),
            b"12345678"
        );

        for (slot, byte) in buffer.bytes.iter_mut().zip(*b"new") {
            slot.write(byte);
        }
        assert_eq!(buffer.initialized_prefix(3).expect("reused prefix"), b"new");
        assert_eq!(
            buffer
                .initialized_prefix(9)
                .expect_err("oversize prefix")
                .kind(),
            ErrorKind::InvalidData
        );
    }
}
