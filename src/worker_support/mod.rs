mod cache;
mod dispatch;
mod lifecycle;
mod pacing;
mod packet_admission;
mod socket_io;
mod sync_buffer;

pub(crate) use cache::CachedClientState;
pub(crate) use dispatch::{
    observe_reply_id_ack, refresh_lock_and_sync_state, send_sync_payload_or_cadence,
    send_user_payload_event,
};
pub(crate) use lifecycle::{run_reresolve_thread, run_watchdog_thread};
pub(crate) use pacing::GlobalSyncPacer;
#[cfg(test)]
pub(crate) use packet_admission::{AdmissionError, IcmpAdmissionInfo, validate_admitted_payload};
pub(crate) use packet_admission::{
    SocketPeerRole, WirePacketAdmission, admit_wire_packet, client_admission_spec,
    log_rejected_packet, record_rejection_stats, upstream_admission_spec,
};
pub(crate) use socket_io::{recv_packet, wait_socket_until_readable};
pub(crate) use sync_buffer::{BufferedSyncUpdate, buffer_sync_event, handle_c2u_session_control};
