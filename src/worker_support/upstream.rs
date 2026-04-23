use super::upstream_ack::consume_reply_id_ack;
use super::{
    CachedClientState, PacketContext, PacketReceiver, ReceivePacketContext, SocketLeg,
    UserPayloadRoute, record_user_payload_route, refresh_lock_and_sync_state,
    upstream_receive_context,
};
use crate::cli::RuntimeConfig;
use crate::flow_state::FlowRuntimeState;
use crate::net::icmp_sequence::SharedIcmpSequenceState;
use crate::net::params::MAX_WIRE_PAYLOAD;
use crate::net::payload::{
    allocate_send_sequence, classify_u2c_event, outbound_payload_event,
    reply_id_negotiation_for_u2c_listener_reply, send_payload,
};
use crate::net::session::{SendOutcome, handle_send_result};
use crate::net::sock_mgr::SocketManager;
use crate::net::sync_icmp::validate_u2c_sync;
use crate::stats::{StatsShard, StatsSink};
use std::io;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) struct UpstreamWorkerContext<'a> {
    pub(crate) t_start: Instant,
    pub(crate) cfg: &'a RuntimeConfig,
    pub(crate) sock_mgr: &'a SocketManager,
    pub(crate) all_sock_mgrs: &'a [Arc<SocketManager>],
    pub(crate) worker_id: usize,
    pub(crate) flow_state: &'a FlowRuntimeState,
    pub(crate) stats: &'a StatsShard,
    pub(crate) client_side_state: &'a SharedIcmpSequenceState,
    pub(crate) upstream_side_state: &'a SharedIcmpSequenceState,
}

pub(crate) fn run_upstream_to_client_thread(context: UpstreamWorkerContext<'_>) {
    let UpstreamWorkerContext {
        t_start,
        cfg,
        sock_mgr,
        worker_id,
        flow_state,
        stats,
        client_side_state,
        upstream_side_state,
        ..
    } = context;
    const C2U: bool = false;
    let mut receiver = PacketReceiver::<{ MAX_WIRE_PAYLOAD }>::new();
    let mut handles = sock_mgr.refresh_handles();
    let mut was_locked = false;
    let mut client_side_cache = client_side_state.cache();
    let mut upstream_side_cache = upstream_side_state.cache();
    let mut cache = CachedClientState::new(C2U, worker_id, cfg, &handles, cfg.debug_logs.handles);
    let mut c2u_cache =
        CachedClientState::new(true, worker_id, cfg, &handles, cfg.debug_logs.handles);
    loop {
        cache.refresh_handles_and_cache(sock_mgr, &mut handles);
        c2u_cache.refresh_from_handles(&handles);
        refresh_lock_and_sync_state(
            cfg,
            flow_state,
            &mut was_locked,
            upstream_side_state,
            &mut upstream_side_cache,
        );
        let upstream_admission = upstream_receive_context(cfg, &handles);
        match receiver.receive(
            &handles.upstream_sock,
            handles
                .upstream
                .policy
                .receive_syscall(handles.upstream.upstream_connected),
            ReceivePacketContext {
                cfg,
                worker_id,
                c2u: C2U,
                socket_leg: SocketLeg::UpstreamFacing,
                receive_context: upstream_admission,
                stats,
            },
        ) {
            Ok(Some((len, admitted))) => {
                let trace = admitted.trace.expect("received packet trace");
                let t_recv = Instant::now();
                log_debug!(
                    cfg.debug_logs.packets,
                    "[worker {}] received {} bytes from upstream socket {:?}",
                    worker_id,
                    len,
                    handles.upstream.upstream_remote_filter
                );
                cache.refresh_handles_and_cache(sock_mgr, &mut handles);
                let locked_now = refresh_lock_and_sync_state(
                    cfg,
                    flow_state,
                    &mut was_locked,
                    upstream_side_state,
                    &mut upstream_side_cache,
                );
                if locked_now {
                    let event = admitted.event;
                    let decision = match classify_u2c_event(cfg, &event, upstream_side_state) {
                        Ok(decision) => decision,
                        Err(err) => {
                            log_debug_dir!(
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "classify_u2c_event rejected packet: {}",
                                err
                            );
                            crate::worker_support::log_packet_disposition(
                                cfg,
                                trace,
                                crate::worker_support::PacketDisposition::DropDuplicate,
                            );
                            continue;
                        }
                    };

                    if decision.requires_sync_validation()
                        && cfg.is_icmp_sync_enabled()
                        && let Some(icmp) = event.icmp_meta()
                        && let Err(err) = validate_u2c_sync(
                            cfg,
                            icmp.seq(),
                            upstream_side_state,
                            &mut upstream_side_cache,
                        )
                    {
                        log_debug_dir!(
                            cfg.debug_logs.drops,
                            worker_id,
                            C2U,
                            "ICMP sync validation failed: {}",
                            err
                        );
                        crate::worker_support::log_packet_disposition(
                            cfg,
                            trace,
                            crate::worker_support::PacketDisposition::DropSyncInvalid,
                        );
                        continue;
                    }

                    if consume_reply_id_ack(
                        &context,
                        &event,
                        trace,
                        t_recv,
                        &mut handles,
                        &mut cache,
                        &mut c2u_cache,
                        &mut client_side_cache,
                        &mut upstream_side_cache,
                    ) {
                        continue;
                    }
                    let source_id = cache.route.icmp_source_id();
                    let reply_id = reply_id_negotiation_for_u2c_listener_reply(
                        &event,
                        cfg.listener_reply_id_request
                            .resolved_reply_id(handles.listener.listen_local_filter.id),
                    )
                    .filter(|_| cfg.listen_proto == crate::cli::SupportedProtocol::ICMP);
                    if !decision.should_send() {
                        crate::worker_support::log_packet_disposition(
                            cfg,
                            trace,
                            match decision {
                                crate::net::payload::U2cDecision::ConsumeCadence => {
                                    crate::worker_support::PacketDisposition::ConsumeCadence
                                }
                                crate::net::payload::U2cDecision::ConsumeSessionControl => {
                                    crate::worker_support::PacketDisposition::ConsumeSessionControl
                                }
                                crate::net::payload::U2cDecision::ForwardPayload
                                | crate::net::payload::U2cDecision::ForwardSessionControl => {
                                    unreachable!("forward decisions send")
                                }
                            },
                        );
                        continue;
                    }
                    if event.is_user_payload() {
                        record_user_payload_route(
                            PacketContext::new(worker_id, t_start, t_recv, cfg, stats, flow_state),
                            UserPayloadRoute::ForwardNow,
                        );
                    }
                    let send_res = {
                        let outbound = match outbound_payload_event(
                            &event,
                            cache.route.icmp_header_id,
                            C2U,
                            allocate_send_sequence(
                                C2U,
                                &event,
                                true,
                                client_side_state,
                                &mut client_side_cache,
                            ),
                            source_id,
                            reply_id,
                        ) {
                            Ok(outbound) => outbound,
                            Err(err) => {
                                log_debug_dir!(
                                    cfg.debug_logs.drops,
                                    worker_id,
                                    C2U,
                                    "outbound payload build error: {}",
                                    err
                                );
                                crate::worker_support::log_packet_disposition(
                                    cfg,
                                    trace,
                                    crate::worker_support::PacketDisposition::SendFailed,
                                );
                                continue;
                            }
                        };
                        send_payload(
                            &handles.client_sock,
                            handles.listener.listener_connected,
                            &cache.route.dest_sa,
                            handles.listener.policy.send_policy,
                            cache.route.source_ip,
                            &outbound,
                        )
                    };
                    handle_send_result(
                        PacketContext::new(worker_id, t_start, t_recv, cfg, stats, flow_state),
                        C2U,
                        &event,
                        SendOutcome {
                            result: &send_res,
                            socket_connected: handles.listener.listener_connected,
                            destination: &cache.route.dest_sa,
                            disconnect: Some((&mut handles, sock_mgr)),
                            trace: Some(trace),
                            trace_kind: crate::net::session::SendTraceKind::Forward,
                        },
                    );
                } else {
                    crate::worker_support::log_packet_disposition(
                        cfg,
                        trace,
                        crate::worker_support::PacketDisposition::DropNoActiveFlow,
                    );
                }
            }
            Ok(None) => {}
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => {
                log_error_dir!(worker_id, C2U, "recv error: {}", e);
                stats.drop_err(C2U);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
