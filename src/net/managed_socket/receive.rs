use pkthere_socket_policy::ReceiveSyscall;
use socket2::Socket;
use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;

/// Per-worker storage for one receive operation.
pub(crate) struct ReceiveBuffer<const CAPACITY: usize> {
    pub(super) bytes: [MaybeUninit<u8>; CAPACITY],
}

impl<const CAPACITY: usize> ReceiveBuffer<CAPACITY> {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [MaybeUninit::uninit(); CAPACITY],
        }
    }

    pub(super) fn initialized_prefix(&self, length: usize) -> io::Result<&[u8]> {
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
    source: Option<SocketAddr>,
}

impl<'a> ReceivedPacket<'a> {
    #[inline]
    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[inline]
    pub(crate) const fn source(&self) -> Option<SocketAddr> {
        self.source
    }
}

pub(super) fn receive<'a, const CAPACITY: usize>(
    socket: &Socket,
    syscall: ReceiveSyscall,
    buffer: &'a mut ReceiveBuffer<CAPACITY>,
) -> io::Result<ReceivedPacket<'a>> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketReceive);
    let (length, source) = match syscall {
        ReceiveSyscall::Recv => (socket.recv(&mut buffer.bytes)?, None),
        ReceiveSyscall::RecvFrom => {
            let (length, source) = socket.recv_from(&mut buffer.bytes)?;
            let source = source.as_socket().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IP receive returned non-IP source metadata",
                )
            })?;
            (length, Some(source))
        }
    };
    // socket2's successful recv/recv_from contract initializes exactly the
    // first `length` bytes.
    let bytes = buffer.initialized_prefix(length)?;
    Ok(ReceivedPacket { bytes, source })
}
