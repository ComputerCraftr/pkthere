mod cache;
mod client;
mod client_dispatch;
mod client_lock;
mod context;
mod dispatch;
mod handshake_trace;
mod lifecycle;
mod pacing;
mod packet_admission;
mod packet_dump;
mod receive;
mod socket_io;
mod sync_buffer;
#[cfg(test)]
pub(crate) mod test_support;
mod upstream;
mod upstream_ack;

pub(crate) use crate::packet_trace::PacketTraceId;
pub(crate) use cache::{CachedClientState, CachedSendRoute};
pub(crate) use client::{ClientWorkerContext, run_client_to_upstream_thread};
pub(crate) use context::{PacketContext, SequenceContext};
pub(crate) use dispatch::{
    ObserveAckResult, UserPayloadRoute, observe_reply_id_ack, record_user_payload_route,
    refresh_lock_and_sync_state, send_payload_event_now, send_sync_payload_or_cadence,
    send_user_payload_event,
};
pub(crate) use lifecycle::{run_reresolve_thread, run_watchdog_thread};
pub(crate) use pacing::GlobalSyncPacer;
#[cfg(test)]
pub(crate) use packet_admission::RejectionReason;
#[cfg(test)]
pub(crate) use packet_admission::WirePacketAdmission;
#[cfg(test)]
pub(crate) use packet_admission::admit_wire_packet;
#[cfg(test)]
pub(crate) use packet_admission::test_support as admission_test_support;
pub(crate) use packet_admission::{SocketLeg, client_receive_context, upstream_receive_context};
pub(crate) use packet_dump::{
    PacketDisposition, admit_received_packet_with_dump, log_packet_disposition,
    log_packet_send_disposition,
};
pub(crate) use receive::{PacketReceiver, ReceivePacketContext};
pub(crate) use socket_io::{recv_packet, wait_socket_until_readable};
pub(crate) use sync_buffer::{BufferedSyncUpdate, buffer_sync_event, handle_c2u_session_control};
pub(crate) use upstream::{UpstreamWorkerContext, run_upstream_to_client_thread};
