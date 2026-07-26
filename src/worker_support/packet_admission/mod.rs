//! Packet admission policy, transport validation, and rejection diagnostics.

mod admitted;
mod endpoint_evidence;
mod rejection;
mod transport;
mod transport_client_flow;
mod transport_context;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod transport_debug_tests;
#[cfg(test)]
mod transport_raw_tests;
#[cfg(test)]
mod transport_shim_tests;
#[cfg(test)]
mod transport_tests;

pub(crate) use pkthere_socket_policy::PeerSourceRequirement;
pub(crate) use rejection::{
    RejectedPacket, RejectedPacketExtent, RejectionLogContext, RejectionReason,
    log_rejected_packet, record_rejection_stats,
};
#[cfg(test)]
pub(crate) use transport::{
    AdmissionStateContext, ProtocolIdRequirement, ReceiveEvidencePolicy, ReceiveSocketContext,
    admit_packet, admit_wire_packet,
};
pub(crate) use transport::{
    AdmittedWirePacket, ReceiveContext, ReceiveNoiseReason, SocketLeg, TransportAdmission,
    WirePacketAdmission, WirePacketRejection, admit_network_layer, admit_packet_with_parsed,
    admit_transport_packet, client_receive_context, transport_requires_authenticated_work,
    upstream_receive_context,
};
