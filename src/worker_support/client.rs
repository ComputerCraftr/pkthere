use super::{CLIENT_TO_UPSTREAM as C2U, GlobalSyncPacer, RECEIVE_ERROR_BACKOFF};
use crate::cli::RuntimeConfig;
use crate::flow_claim::FlowClaimTable;
use crate::flow_state::{FlowReaderLane, FlowRuntimeState};
use crate::net::icmp_sequence::SharedIcmpSequenceState;
use crate::net::sock_mgr::SocketManager;
use crate::runtime_support::{RuntimeFailure, ShutdownController};
use crate::stats::{StatsRecorder, StatsSink};
use std::io;
use std::sync::Arc;
use std::time::Instant;

pub(crate) struct ClientWorkerContext<'a> {
    pub(crate) t_start: Instant,
    pub(crate) cfg: &'a RuntimeConfig,
    pub(crate) sock_mgr: &'a SocketManager,
    pub(crate) all_sock_mgrs: &'a [Arc<SocketManager>],
    pub(crate) worker_id: usize,
    pub(crate) flow_lane: FlowReaderLane,
    pub(crate) flow_state: &'a FlowRuntimeState,
    pub(crate) stats: &'a mut StatsRecorder,
    pub(crate) client_side_state: &'a SharedIcmpSequenceState,
    pub(crate) upstream_side_state: &'a SharedIcmpSequenceState,
    pub(crate) sync_pacer: Option<&'a GlobalSyncPacer>,
    pub(crate) flow_claims: Option<&'a FlowClaimTable>,
    pub(crate) worker_pair_id: usize,
    pub(crate) exit_code_set: &'a ShutdownController,
}

pub(super) fn handle_receive_error(context: &mut ClientWorkerContext<'_>, error: io::Error) {
    if error.kind() != io::ErrorKind::WouldBlock && error.kind() != io::ErrorKind::TimedOut {
        log_error_dir!(context.worker_id, C2U, "recv error: {}", error);
        context.stats.receive_error(C2U);
        crate::authority::audited_thread_sleep(RECEIVE_ERROR_BACKOFF);
    }
}

pub(super) fn request_fatal_exit_after_client_lock_failure(shutdown: &ShutdownController) {
    shutdown.request_current_fatal(RuntimeFailure::fatal(format_args!(
        "client lock transaction failed"
    )));
}

pub(super) fn lease_due_sync_send(
    flow_state: &FlowRuntimeState,
    pacer: &GlobalSyncPacer,
    now: Instant,
) -> Result<
    Option<crate::flow_state::SyncSendLease>,
    crate::flow_state::ReplyIdHandshakeInvariantError,
> {
    if !pacer.is_due(now) {
        return Ok(None);
    }
    let Some(lease) = flow_state.lease_sync_send()? else {
        return Ok(None);
    };
    if pacer.try_acquire_send(now) {
        return Ok(Some(lease));
    }
    flow_state.complete_sync_send(lease, false)?;
    Ok(None)
}

pub(crate) fn run_client_to_upstream_thread(context: ClientWorkerContext<'_>) {
    super::client_loop::run(context);
}

#[cfg(test)]
mod tests;
