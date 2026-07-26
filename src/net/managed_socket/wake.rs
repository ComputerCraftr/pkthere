use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::AtomicU64;

/// A coalescing, process-local wake channel owned by the socket authority.
///
/// The pair is deliberately implemented here so lifecycle code never performs
/// raw socket association or receive syscalls outside `managed_socket`.
pub(crate) struct ManagedWakePair {
    sender: UdpSocket,
    pub(super) receiver: UdpSocket,
    pub(super) wake_state:
        crate::authority::AuthorityAtomic<crate::authority::tags::WakeGeneration, AtomicU64>,
}

impl ManagedWakePair {
    pub(crate) fn new() -> io::Result<Self> {
        let receiver = {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::SocketBind);
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?
        };
        {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::SocketConfigure);
            receiver.set_nonblocking(true)?;
        }
        let sender = {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::SocketBind);
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?
        };
        let receiver_address = {
            let _operation = crate::authority::audited_operation(
                crate::authority::OperationId::SocketLocalInspection,
            );
            receiver.local_addr()?
        };
        {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::SocketConnect);
            sender.connect(receiver_address)?;
        }
        {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::SocketConfigure);
            sender.set_nonblocking(true)?;
        }
        Ok(Self {
            sender,
            receiver,
            wake_state: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::WakeCoalescing,
            ),
        })
    }

    pub(crate) const fn receiver(&self) -> &UdpSocket {
        &self.receiver
    }

    pub(crate) fn notify(&self) -> io::Result<()> {
        let publication =
            crate::atomic_core::publish_wake_generation(&self.wake_state).map_err(|error| {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "managed wake generation exhausted: {error:?}"
                ));
                io::Error::other("managed wake generation exhausted")
            })?;
        if !publication.send_wake {
            return Ok(());
        }
        let sent = {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::WakeSocketSend);
            self.sender.send(&[1])
        };
        if let Err(error) = sent {
            crate::atomic_core::clear_wake_pending(&self.wake_state);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn drain(&self) -> io::Result<()> {
        let mut byte = [0_u8; 1];
        loop {
            loop {
                match self.receive_wake(&mut byte) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            // The queue is empty while the old pending generation is still
            // visible. Clear it, then recheck the queue. A producer before the
            // clear was coalesced into the maintenance pass already in
            // progress; a producer after the clear must enqueue a new byte.
            let cleared_generation = crate::atomic_core::clear_wake_pending(&self.wake_state);
            match self.receive_wake(&mut byte) {
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if crate::atomic_core::wake_drain_is_stable(
                        &self.wake_state,
                        cleared_generation,
                    ) {
                        return Ok(());
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn receive_wake(&self, byte: &mut [u8; 1]) -> io::Result<usize> {
        let _operation =
            crate::authority::audited_operation(crate::authority::OperationId::WakeSocketReceive);
        self.receiver.recv(byte)
    }
}
