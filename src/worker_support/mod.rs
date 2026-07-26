mod cache;
#[cfg(all(test, not(miri)))]
pub(crate) use cache::tests::test_config as cache_test_config;
mod client;
mod client_dispatch;
mod client_lock;
mod client_loop;
mod client_process;
mod client_process_outbound;
mod constants;
mod context;
mod dispatch;
mod errors;
mod handshake_trace;
#[cfg(all(test, not(miri)))]
mod icmp_pipeline_fixture;
mod lifecycle;
mod pacing;
mod packet_admission;
mod packet_dump;
mod pipeline_audit;
mod receive;
mod reresolve_publication;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod reresolve_publication_loom;
mod stale_association;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod stale_association_loom;
mod sync_buffer;
#[cfg(all(test, not(miri)))]
pub(crate) mod test_support;
mod upstream;
mod upstream_ack;
#[cfg(all(test, not(miri)))]
mod upstream_overlap_tests;
mod upstream_retry;
mod work_budget;
use constants::{CLIENT_TO_UPSTREAM, RECEIVE_ERROR_BACKOFF, UPSTREAM_TO_CLIENT};
use errors::{
    flow_authority_io_error, flow_mutation_io_error, record_sequence_rejection,
    reservation_io_error,
};

pub(crate) use crate::diagnostics::PacketTraceId;
#[cfg(all(test, not(miri)))]
pub(crate) use cache::WorkerStateOutcome;
pub(crate) use cache::{CachedClientState, CachedSendRoute};
pub(crate) use cache::{auxiliary_descriptor_cache_lane, descriptor_cache_lane_count};
pub(crate) use client::{ClientWorkerContext, run_client_to_upstream_thread};
pub(crate) use context::{
    PacketContext, SequenceContext, StableForwardPermit, StableProtocolReservation, StableSendCore,
};
pub(crate) use dispatch::{
    ObserveAckResult, UserPayloadRoute, observe_reply_id_ack, perform_sync_session_transition,
    record_user_payload_route, send_payload_event_now_stable, send_sync_payload_or_cadence,
    send_user_payload_event,
};
pub(crate) use lifecycle::{run_reresolve_thread, run_watchdog_thread};
pub(crate) use pacing::GlobalSyncPacer;
pub(crate) use packet_admission::RejectionReason;
#[cfg(test)]
pub(crate) use packet_admission::WirePacketRejection;
#[cfg(test)]
pub(crate) use packet_admission::admit_wire_packet;
#[cfg(test)]
pub(crate) use packet_admission::test_support as admission_test_support;
pub(crate) use packet_admission::{SocketLeg, client_receive_context, upstream_receive_context};
pub(crate) use packet_dump::{
    PacketDisposition, PacketDumpAdmissionContext, ReceivedPacketAdmission,
    admit_received_packet_with_dump, configure_packet_diagnostics,
    flush_completed_packet_diagnostics, log_packet_disposition, log_packet_send_disposition,
};
pub(crate) use pipeline_audit::PipelineStage;
#[cfg(all(test, not(miri)))]
pub(crate) use receive::ReceiveAuthority;
pub(crate) use receive::{PacketReceiver, ReceiveMutationAuthority, ReceivePacketContext};
pub(crate) use sync_buffer::{
    BufferedSyncUpdate, SessionControlReplyContext, buffer_sync_event, handle_c2u_session_control,
};
pub(crate) use upstream::{UpstreamWorkerContext, run_upstream_to_client_thread};
