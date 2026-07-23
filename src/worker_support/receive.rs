use super::packet_admission::{
    AdmittedWirePacket, ReceiveContext, SocketLeg, WirePacketAdmission, log_rejected_packet,
    record_rejection_stats,
};
use super::{PacketTraceId, admit_received_packet_with_dump};
use crate::cli::RuntimeConfig;
use crate::net::managed_socket::{ManagedSocket, ReceiveBuffer};
use crate::stats::StatsShard;
use pkthere_socket_policy::ReceiveSyscall;
use std::io;

pub(crate) struct PacketReceiver<const CAPACITY: usize> {
    buffer: ReceiveBuffer<CAPACITY>,
    next_packet_id: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct ReceivePacketContext<'a> {
    pub(crate) cfg: &'a RuntimeConfig,
    pub(crate) worker_id: usize,
    pub(crate) c2u: bool,
    pub(crate) socket_leg: SocketLeg,
    pub(crate) receive_context: ReceiveContext,
    pub(crate) stats: &'a StatsShard,
}

impl<const CAPACITY: usize> PacketReceiver<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            buffer: ReceiveBuffer::new(),
            next_packet_id: 1,
        }
    }

    pub(crate) fn receive<'a>(
        &'a mut self,
        socket: &ManagedSocket,
        syscall: ReceiveSyscall,
        context: ReceivePacketContext<'_>,
    ) -> io::Result<Option<(usize, AdmittedWirePacket<'a>)>> {
        let packet = socket.receive(syscall, &mut self.buffer)?;
        let length = packet.bytes().len();
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
        let bytes = packet.bytes();
        let trace = PacketTraceId {
            worker_id: context.worker_id,
            c2u: context.c2u,
            packet_id,
        };
        match admit_received_packet_with_dump(
            context.cfg,
            trace,
            context.receive_context,
            bytes,
            packet.source(),
        ) {
            WirePacketAdmission::Accepted(admitted) => Ok(Some((length, admitted))),
            WirePacketAdmission::ReceiveNoise(_) => Ok(None),
            WirePacketAdmission::Filtered(rejected) => {
                record_rejection_stats(context.stats, context.c2u, rejected);
                log_rejected_packet(
                    context.worker_id,
                    context.c2u,
                    context.cfg,
                    context.socket_leg,
                    rejected,
                    context.receive_context,
                    Some(bytes),
                );
                Ok(None)
            }
        }
    }
}
