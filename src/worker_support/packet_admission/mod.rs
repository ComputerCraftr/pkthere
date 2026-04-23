//! Packet admission policy, transport validation, and rejection diagnostics.

mod raw_ip;
mod rejection;
mod transport;

pub(crate) use pkthere_socket_policy::PeerSourceRequirement;
#[cfg(test)]
pub(crate) use rejection::RejectedPacket;
pub(crate) use rejection::{RejectionReason, log_rejected_packet, record_rejection_stats};
pub(crate) use transport::{
    AdmittedWirePacket, ReceiveContext, ReceiveNoiseReason, SocketLeg, WirePacketAdmission,
    admit_wire_packet_with_parsed, client_receive_context, upstream_receive_context,
};
#[cfg(test)]
pub(crate) use transport::{admit_wire_packet, test_support};
