use super::client_dispatch::{process_client_packet, process_sync_packet};
use super::{
    CachedClientState, GlobalSyncPacer, PacketContext, PacketReceiver, ReceivePacketContext,
    SocketLeg, client_receive_context, refresh_lock_and_sync_state, send_sync_payload_or_cadence,
    wait_socket_until_readable,
};
use crate::cli::RuntimeConfig;
use crate::flow_claim::FlowClaimTable;
use crate::flow_state::FlowRuntimeState;
use crate::net::icmp_sequence::SharedIcmpSequenceState;
use crate::net::params::MAX_WIRE_PAYLOAD;
use crate::net::sock_mgr::SocketManager;
use crate::stats::{StatsShard, StatsSink};
use std::io;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const C2U: bool = true;
const RECEIVE_ERROR_BACKOFF: Duration = Duration::from_millis(10);
const UNLOCKED_SYNC_BACKOFF: Duration = Duration::from_millis(1);

pub(crate) struct ClientWorkerContext<'a> {
    pub(crate) t_start: Instant,
    pub(crate) cfg: &'a RuntimeConfig,
    pub(crate) sock_mgr: &'a SocketManager,
    pub(crate) all_sock_mgrs: &'a [Arc<SocketManager>],
    pub(crate) worker_id: usize,
    pub(crate) flow_state: &'a FlowRuntimeState,
    pub(crate) stats: &'a StatsShard,
    pub(crate) client_side_state: &'a SharedIcmpSequenceState,
    pub(crate) upstream_side_state: &'a SharedIcmpSequenceState,
    pub(crate) sync_pacer: Option<&'a GlobalSyncPacer>,
    pub(crate) flow_claims: Option<&'a FlowClaimTable>,
    pub(crate) worker_pair_id: usize,
}

fn handle_receive_error(context: &ClientWorkerContext<'_>, error: io::Error) {
    if error.kind() != io::ErrorKind::WouldBlock && error.kind() != io::ErrorKind::TimedOut {
        log_error_dir!(context.worker_id, C2U, "recv error: {}", error);
        context.stats.drop_err(C2U);
        thread::sleep(RECEIVE_ERROR_BACKOFF);
    }
}

pub(crate) fn run_client_to_upstream_thread(context: ClientWorkerContext<'_>) {
    let mut receiver = PacketReceiver::<{ MAX_WIRE_PAYLOAD }>::new();
    let mut latest_sync_payload = None;
    let mut handles = context.sock_mgr.refresh_handles();
    let mut was_locked = false;
    let mut client_side_cache = context.client_side_state.cache();
    let mut upstream_side_cache = context.upstream_side_state.cache();
    let mut cache = CachedClientState::new(
        C2U,
        context.worker_id,
        context.cfg,
        &handles,
        context.cfg.debug_logs.handles,
    );

    loop {
        cache.refresh_handles_and_cache(context.sock_mgr, &mut handles);
        let locked_now = refresh_lock_and_sync_state(
            context.cfg,
            context.flow_state,
            &mut was_locked,
            context.client_side_state,
            &mut client_side_cache,
        );

        if context.cfg.is_icmp_sync_enabled() && locked_now {
            let Some(pacer) = context.sync_pacer else {
                log_error_dir!(
                    context.worker_id,
                    C2U,
                    "sync pacing state missing while ICMP sync mode is enabled"
                );
                thread::sleep(RECEIVE_ERROR_BACKOFF);
                continue;
            };
            let now = Instant::now();
            if pacer.try_acquire_send(now) {
                if let Err(error) = send_sync_payload_or_cadence(
                    PacketContext::new(
                        context.worker_id,
                        context.t_start,
                        now,
                        context.cfg,
                        context.stats,
                        context.flow_state,
                    ),
                    &handles,
                    &cache,
                    (context.upstream_side_state, &mut upstream_side_cache),
                    latest_sync_payload.take().as_ref(),
                ) {
                    log_debug_dir!(
                        context.cfg.debug_logs.drops,
                        context.worker_id,
                        C2U,
                        "outbound payload build error: {}",
                        error
                    );
                }
                continue;
            }
            match wait_socket_until_readable(&handles.client_sock, pacer.poll_wait()) {
                Ok(false) => continue,
                Ok(true) => {}
                Err(error) => {
                    log_error_dir!(context.worker_id, C2U, "poll/read wait error: {}", error);
                    context.stats.drop_err(C2U);
                    thread::sleep(RECEIVE_ERROR_BACKOFF);
                    continue;
                }
            }
            let receive_context = client_receive_context(
                context.cfg,
                &handles,
                handles.listener.listener_flow.inbound,
                context.flow_state.pending_icmp_client_lock(),
            );
            match receiver.receive(
                &handles.client_sock,
                handles
                    .listener
                    .policy
                    .receive_syscall(handles.listener_connected()),
                ReceivePacketContext {
                    cfg: context.cfg,
                    worker_id: context.worker_id,
                    c2u: C2U,
                    socket_leg: SocketLeg::ClientFacing,
                    receive_context,
                    stats: context.stats,
                },
            ) {
                Ok(Some((_, admitted))) => process_sync_packet(
                    &context,
                    &mut handles,
                    &cache,
                    &mut client_side_cache,
                    &mut latest_sync_payload,
                    admitted,
                ),
                Ok(None) => {}
                Err(error) => handle_receive_error(&context, error),
            }
            continue;
        }
        if context.cfg.is_icmp_sync_enabled() && handles.listener_connected() {
            thread::sleep(UNLOCKED_SYNC_BACKOFF);
            continue;
        }

        let expected_inbound = context
            .flow_state
            .is_locked()
            .then_some(handles.listener.listener_flow.inbound)
            .flatten();
        let receive_context = client_receive_context(
            context.cfg,
            &handles,
            expected_inbound,
            context.flow_state.pending_icmp_client_lock(),
        );
        match receiver.receive(
            &handles.client_sock,
            handles
                .listener
                .policy
                .receive_syscall(handles.listener_connected()),
            ReceivePacketContext {
                cfg: context.cfg,
                worker_id: context.worker_id,
                c2u: C2U,
                socket_leg: SocketLeg::ClientFacing,
                receive_context,
                stats: context.stats,
            },
        ) {
            Ok(Some((length, admitted))) => {
                log_debug!(
                    context.cfg.debug_logs.packets,
                    "[worker {}] received {} bytes from client socket",
                    context.worker_id,
                    length
                );
                process_client_packet(
                    &context,
                    &mut handles,
                    &mut cache,
                    &mut client_side_cache,
                    &mut upstream_side_cache,
                    &mut was_locked,
                    admitted,
                );
            }
            Ok(None) => {}
            Err(error) => handle_receive_error(&context, error),
        }
    }
}
