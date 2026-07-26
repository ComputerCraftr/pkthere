use super::dispatch::{PayloadSendResult, SendAccounting};
use super::handshake_trace::{log_handshake_ack_ignored, log_handshake_ack_matched};
use super::upstream::UpstreamWorkerContext;
use super::{
    CachedClientState, ObserveAckResult, PacketContext, PacketDisposition, PacketTraceId,
    SequenceContext, UPSTREAM_TO_CLIENT as C2U, log_packet_disposition, observe_reply_id_ack,
};
use crate::cli::{SupportedProtocol, WorkerFlowMode};
use crate::flow_state::ClientFlowReservation;
use crate::net::icmp_sequence::IcmpSequenceCache;
use crate::net::payload::PayloadEvent;
use crate::net::session::HandledSendOutcome;
use crate::net::sock_mgr::{ManagerError, SocketHandles};
use crate::runtime_support::{FATAL_EXIT, ShutdownController};
use crate::stats::StatsSink;
use std::sync::atomic::Ordering;
use std::time::Instant;

fn rollback_after_topology_update_failure(
    flow_state: &crate::flow_state::FlowRuntimeState,
    stats: &mut dyn StatsSink,
    exit_code_set: &ShutdownController,
    token: crate::flow_state::ReplyIdHandshakeCommitToken,
    topology_error: &dyn std::fmt::Display,
) -> Option<crate::flow_state::HandshakeRollbackOutcome> {
    match flow_state.rollback_upstream_reply_id_handshake(token, Instant::now()) {
        Ok(outcome) => Some(outcome),
        Err(rollback_error) => {
            log_error!(
                "upstream peer-ID topology update failed ({topology_error}); handshake rollback failed fatally: {rollback_error:?}"
            );
            stats.invariant_failure(true);
            exit_code_set.store(FATAL_EXIT, Ordering::Release);
            None
        }
    }
}

fn mark_manager_published(
    flow_state: &crate::flow_state::FlowRuntimeState,
    flow_transaction: &ClientFlowReservation<'_>,
    token: crate::flow_state::ReplyIdHandshakeCommitToken,
) -> Result<
    crate::flow_state::ReplyIdHandshakeManagerReceipt,
    crate::flow_state::FlowMutationError<crate::flow_state::ReplyIdHandshakeTransitionError>,
> {
    flow_state.mark_upstream_reply_id_manager_published_under(flow_transaction, token)
}

fn commit_after_topology_update(
    flow_state: &crate::flow_state::FlowRuntimeState,
    flow_transaction: &ClientFlowReservation<'_>,
    receipt: crate::flow_state::ReplyIdHandshakeManagerReceipt,
) -> Result<
    crate::flow_state::ReplyIdHandshakeActivationLease,
    crate::flow_state::FlowMutationError<crate::flow_state::ReplyIdHandshakeTransitionError>,
> {
    flow_state.commit_upstream_reply_id_handshake_under(flow_transaction, receipt)
}

#[allow(clippy::too_many_arguments)]
fn flush_reply_id_payload(
    context: &mut UpstreamWorkerContext<'_>,
    lease: crate::flow_state::ReplyIdPayloadSendLease,
    handles: &SocketHandles,
    c2u_cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
) -> Option<crate::flow_state::DeferredPeerControl> {
    let payload = lease.payload();
    let buffered_event = payload.as_event();
    let payload_len = payload.payload_len();
    let payload_received_at = payload.received_at();
    let payload_trace = payload.trace();
    let stable_permit = match super::context::prepared_upstream_permit(
        context.flow_state,
        context.flow_lane,
        handles,
        context.upstream_side_state,
        upstream_side_cache,
    ) {
        Ok(permit) => permit,
        Err(error) => {
            let timeout_requested = context
                .flow_state
                .release_upstream_reply_id_payload_send(lease)
                .unwrap_or_else(|_| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "buffered payload ownership was lost before stable send"
                    ))
                });
            log_debug_dir!(
                context.cfg.debug_logs.drops,
                context.worker_id,
                C2U,
                "buffered payload stable authority unavailable; payload retained for {}: {}",
                if timeout_requested {
                    "pending timeout"
                } else {
                    "internal retry"
                },
                error,
            );
            return None;
        }
    };
    match super::dispatch::send_payload_event_now_with_accounting_stable(
        &mut PacketContext::new(
            context.worker_id,
            context.t_start,
            payload.received_at(),
            context.cfg,
            context.stats,
            context.flow_state,
        ),
        &buffered_event,
        handles,
        c2u_cache,
        SequenceContext::new(
            context.client_side_state,
            client_side_cache,
            context.upstream_side_state,
            upstream_side_cache,
        ),
        super::dispatch::StableSendAccounting {
            trace: payload.trace(),
            accounting: SendAccounting {
                success: false,
                activation_recovery: true,
            },
        },
        stable_permit,
    ) {
        Ok(PayloadSendResult {
            outcome: HandledSendOutcome::Sent {
                used_unconnected, ..
            },
            attempted_at,
            completed_at,
            deferred_control,
            ..
        }) => {
            let timeout_requested = match context
                .flow_state
                .complete_upstream_reply_id_payload_send(lease)
            {
                Ok(timeout_requested) => timeout_requested,
                Err(_) => {
                    log_error!(
                        "buffered payload send lease was lost after a successful socket send"
                    );
                    context.stats.invariant_failure(true);
                    context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                    return None;
                }
            };
            if timeout_requested {
                log_debug_dir!(
                    context.cfg.debug_logs.drops,
                    context.worker_id,
                    C2U,
                    "buffered payload syscall completed after timeout/reset won; suppressing forwarding accounting"
                );
                if let Some(trace) = payload_trace {
                    log_packet_disposition(
                        context.cfg,
                        trace,
                        PacketDisposition::HandshakeTimeoutDrop,
                    );
                }
                return None;
            }
            if context.cfg.stats_interval_mins != 0 {
                context.stats.send_add(
                    true,
                    payload_len as u64,
                    payload_received_at,
                    attempted_at,
                    completed_at,
                );
            }
            if let Some(trace) = payload_trace {
                super::log_packet_send_disposition(
                    context.cfg,
                    trace,
                    PacketDisposition::Forwarded,
                    used_unconnected,
                );
            }
            deferred_control
        }
        Ok(PayloadSendResult {
            outcome: HandledSendOutcome::Failed | HandledSendOutcome::Deferred,
            deferred_control,
            ..
        }) => {
            let timeout_requested = match context
                .flow_state
                .release_upstream_reply_id_payload_send(lease)
            {
                Ok(timeout_requested) => timeout_requested,
                Err(_) => {
                    log_error!("buffered payload ownership was lost after a failed socket send");
                    context.stats.invariant_failure(true);
                    context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                    return None;
                }
            };
            log_debug_dir!(
                context.cfg.debug_logs.drops,
                context.worker_id,
                C2U,
                "buffered payload flush did not complete; payload retained for {}",
                if timeout_requested {
                    "pending timeout"
                } else {
                    "internal retry"
                }
            );
            if timeout_requested && let Some(trace) = payload_trace {
                log_packet_disposition(context.cfg, trace, PacketDisposition::HandshakeTimeoutDrop);
            }
            deferred_control
        }
        Err(error) => {
            let timeout_requested = match context
                .flow_state
                .release_upstream_reply_id_payload_send(lease)
            {
                Ok(timeout_requested) => timeout_requested,
                Err(_) => {
                    log_error!("buffered payload ownership was lost after a socket send error");
                    context.stats.invariant_failure(true);
                    context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                    return None;
                }
            };
            log_debug_dir!(
                context.cfg.debug_logs.drops,
                context.worker_id,
                C2U,
                "buffered payload flush error; payload retained for {}: {}",
                if timeout_requested {
                    "pending timeout"
                } else {
                    "internal retry"
                },
                error,
            );
            if timeout_requested && let Some(trace) = payload_trace {
                log_packet_disposition(context.cfg, trace, PacketDisposition::HandshakeTimeoutDrop);
            }
            None
        }
    }
}

pub(super) fn retry_due_reply_id_payload(
    context: &mut UpstreamWorkerContext<'_>,
    handles: &SocketHandles,
    c2u_cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
) -> (bool, Option<crate::flow_state::DeferredPeerControl>) {
    let Some(lease) = context
        .flow_state
        .lease_due_upstream_reply_id_payload(Instant::now())
    else {
        return (false, None);
    };
    let deferred = flush_reply_id_payload(
        context,
        lease,
        handles,
        c2u_cache,
        client_side_cache,
        upstream_side_cache,
    );
    (true, deferred)
}

fn update_upstream_peer_ids(
    context: &mut UpstreamWorkerContext<'_>,
    handles: &SocketHandles,
    observed_topology_epoch: u64,
    peer_source_id: u16,
    peer_reply_id: u16,
) -> Result<Option<crate::net::sock_mgr::PublishedUpdate>, ManagerError> {
    let changed = handles.upstream.upstream_remote_filter.id() != peer_reply_id
        || handles
            .upstream
            .upstream_flow
            .inbound
            .is_some_and(|flow| flow.src.id() != peer_source_id)
        || handles
            .upstream
            .upstream_flow
            .outbound
            .is_some_and(|flow| flow.dst.id() != peer_reply_id);
    if context.cfg.upstream_proto != SupportedProtocol::ICMP || !changed {
        return Ok(None);
    }

    log_info!(
        "Updating upstream ICMP peer IDs to source {}, reply {}",
        peer_source_id,
        peer_reply_id
    );
    if context.cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
        let managers = context
            .all_sock_mgrs
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>();
        let update = crate::net::sock_mgr::SocketManager::set_upstream_peer_ids_group_at_topology(
            &managers,
            context.sock_mgr.socket_slot(),
            observed_topology_epoch,
            peer_source_id,
            peer_reply_id,
        )?
        .into_iter()
        .find(|update| {
            update.handles.listener.evidence_key.socket_slot == context.sock_mgr.socket_slot()
        })
        .ok_or_else(|| ManagerError::TransactionFailed {
            operation: "publish shared upstream peer IDs",
            cause: "shared manager publication omitted the local socket manager".into(),
            journal: Vec::new(),
        })?;
        Ok(Some(update))
    } else {
        let update = crate::net::sock_mgr::SocketManager::set_upstream_peer_ids_group_at_topology(
            &[context.sock_mgr],
            context.sock_mgr.socket_slot(),
            observed_topology_epoch,
            peer_source_id,
            peer_reply_id,
        )?
        .pop()
        .ok_or_else(|| ManagerError::TransactionFailed {
            operation: "publish upstream peer IDs",
            cause: "single-manager publication returned no update".into(),
            journal: Vec::new(),
        })?;
        Ok(Some(update))
    }
}

fn consume_session_activated(
    context: &mut UpstreamWorkerContext<'_>,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
    received_at: Instant,
) -> bool {
    let Some(crate::net::framing_shim::IcmpTunnelControl::SessionActivated(activated)) =
        event.icmp_meta().and_then(|icmp| icmp.control())
    else {
        return false;
    };
    let session = activated.session_key().session_id();
    let evidence = context
        .upstream_side_state
        .outbound_data_evidence(session, activated.accepted_sequence());
    let result = if evidence == crate::net::icmp_sequence::DataSequenceEvidenceState::InFlight {
        match context.upstream_side_state.defer_outbound_data_control(
            session,
            crate::flow_state::DeferredPeerControl::SessionActivated {
                control: activated,
                observed_at: received_at,
            },
        ) {
            crate::net::icmp_sequence::DeferredDataControlOutcome::Deferred => Ok(true),
            crate::net::icmp_sequence::DeferredDataControlOutcome::Apply(_) => {
                context.flow_state.observe_upstream_session_activated(
                    activated,
                    received_at,
                    crate::net::icmp_sequence::DataSequenceEvidenceState::Sent,
                )
            }
            crate::net::icmp_sequence::DeferredDataControlOutcome::Rejected => Ok(false),
        }
    } else {
        context
            .flow_state
            .observe_upstream_session_activated(activated, received_at, evidence)
    };
    match result {
        Ok(true) => {}
        Ok(false) => context.stats.handshake_stale_ack(),
        Err(_) => {
            context.stats.invariant_failure(true);
            context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
        }
    }
    log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeSessionControl);
    true
}

#[allow(clippy::too_many_arguments)]
fn consume_session_pool_control(
    context: &mut UpstreamWorkerContext<'_>,
    flow_transaction: &mut Option<ClientFlowReservation<'_>>,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
    received_at: Instant,
    handles: &mut SocketHandles,
    c2u_cache: &mut CachedClientState,
    upstream_side_cache: &mut IcmpSequenceCache,
) -> bool {
    let Some(icmp) = event.icmp_meta() else {
        return false;
    };
    if let Some(crate::net::framing_shim::IcmpTunnelControl::GenerationAdvanceAck(advance)) =
        icmp.control()
    {
        let candidate_deadline =
            received_at + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs);
        match context.flow_state.accept_upstream_generation_advance_ack(
            advance,
            icmp.seq(),
            received_at,
            candidate_deadline,
        ) {
            Ok(true) => {
                drop(flow_transaction.take());
                if let Err(error) = super::dispatch::retry_due_upstream_negotiation(
                    &mut PacketContext::new(
                        context.worker_id,
                        context.t_start,
                        received_at,
                        context.cfg,
                        context.stats,
                        context.flow_state,
                    ),
                    handles,
                    c2u_cache,
                    context.upstream_side_state,
                    upstream_side_cache,
                    None,
                ) {
                    log_error!(
                        "ICMP generation-advance negotiation retry failed fatally: {}",
                        error
                    );
                    context.stats.invariant_failure(true);
                    context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                }
            }
            Ok(false) => context.stats.handshake_stale_ack(),
            Err(_) => {
                context.stats.invariant_failure(true);
                context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
            }
        }
        log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeSessionControl);
        return true;
    }

    let Some(reset) = icmp.reset_required() else {
        return false;
    };
    let expected_ack_destination_id = match c2u_cache.expected_upstream_ack_destination_id(handles)
    {
        Ok(id) => id,
        Err(error) => {
            log_error!("ICMP reset destination identity is unresolved: {}", error);
            context.stats.invariant_failure(true);
            context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
            log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeSessionControl);
            return true;
        }
    };
    let candidate_deadline =
        received_at + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs);
    let rollover_recovered = match context.flow_state.accept_upstream_rollover_challenge(
        reset,
        expected_ack_destination_id,
        received_at,
        candidate_deadline,
    ) {
        Ok(recovered) => recovered,
        Err(error) => {
            log_error!("ICMP generation rollover recovery failed: {}", error);
            context.stats.invariant_failure(true);
            context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
            log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeSessionControl);
            return true;
        }
    };
    let (payload_recovered, payload_control_due) = if rollover_recovered {
        (false, false)
    } else {
        let recovered = context.flow_state.recover_upstream_session_under(
            flow_transaction.as_ref().unwrap_or_else(|| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "session recovery lost its flow reservation"
                ))
            }),
            crate::flow_state::UpstreamRecoveryRequest {
                sequences: context.upstream_side_state,
                reset,
                expected_ack_destination_id,
                observed_at: received_at,
                absolute_deadline: received_at
                    + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs),
                started_s: received_at
                    .saturating_duration_since(context.t_start)
                    .as_secs()
                    .max(1),
            },
        );
        match recovered {
            Ok(crate::flow_state::UpstreamSessionRecovery::Deferred) => (true, false),
            Ok(crate::flow_state::UpstreamSessionRecovery::Ignored) => (false, false),
            Ok(crate::flow_state::UpstreamSessionRecovery::Recovered {
                handshake,
                retired_sessions,
            }) => {
                context
                    .upstream_side_state
                    .retire_outbound_sessions(&retired_sessions);
                (true, handshake.should_send_control())
            }
            Err(error) => {
                log_error!("ICMP reset recovery state failed fatally: {:?}", error);
                context.stats.invariant_failure(true);
                context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                (false, false)
            }
        }
    };
    if rollover_recovered || payload_control_due {
        drop(flow_transaction.take());
        if let Err(error) = super::dispatch::retry_due_upstream_negotiation(
            &mut PacketContext::new(
                context.worker_id,
                context.t_start,
                received_at,
                context.cfg,
                context.stats,
                context.flow_state,
            ),
            handles,
            c2u_cache,
            context.upstream_side_state,
            upstream_side_cache,
            None,
        ) {
            log_error!("ICMP reset negotiation retry failed fatally: {}", error);
            context.stats.invariant_failure(true);
            context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
        }
    } else if !payload_recovered {
        context.stats.handshake_stale_ack();
    }
    log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeSessionControl);
    true
}

#[allow(clippy::too_many_arguments)]
pub(super) fn consume_reply_id_ack(
    context: &mut UpstreamWorkerContext<'_>,
    flow_transaction: &mut Option<ClientFlowReservation<'_>>,
    observed_topology_epoch: u64,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
    received_at: Instant,
    handles: &mut SocketHandles,
    client_cache: &mut CachedClientState,
    c2u_cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
) -> bool {
    if consume_session_activated(context, event, trace, received_at) {
        return true;
    }
    if consume_session_pool_control(
        context,
        flow_transaction,
        event,
        trace,
        received_at,
        handles,
        c2u_cache,
        upstream_side_cache,
    ) {
        return true;
    }
    match observe_reply_id_ack(
        context.cfg,
        event,
        handles,
        context.flow_state,
        received_at,
        trace,
    ) {
        ObserveAckResult::Matched {
            token,
            peer_source_id,
            peer_reply_id,
            trigger_trace,
            handshake_trace,
        } => {
            let Some(session_id) = event.icmp_meta().map(|icmp| icmp.session_id()) else {
                drop(flow_transaction.take());
                log_error!("matched ICMP reply-ID ACK did not carry session metadata");
                return true;
            };
            let publication = match update_upstream_peer_ids(
                context,
                handles,
                observed_topology_epoch,
                peer_source_id,
                peer_reply_id,
            ) {
                Ok(updated) => updated,
                Err(error) => {
                    let Some(rollback) = rollback_after_topology_update_failure(
                        context.flow_state,
                        context.stats,
                        context.exit_code_set,
                        token,
                        &error,
                    ) else {
                        return true;
                    };
                    drop(flow_transaction.take());
                    match rollback {
                        crate::flow_state::HandshakeRollbackOutcome::Retryable => {}
                        crate::flow_state::HandshakeRollbackOutcome::TimedOut { payload } => {
                            if let Some(trace) = payload.trace() {
                                log_packet_disposition(
                                    context.cfg,
                                    trace,
                                    PacketDisposition::HandshakeTimeoutDrop,
                                );
                            }
                        }
                        crate::flow_state::HandshakeRollbackOutcome::ResetApplied { payload } => {
                            if let Some(trace) = payload.trace() {
                                log_packet_disposition(
                                    context.cfg,
                                    trace,
                                    PacketDisposition::HandshakeResetDrop,
                                );
                            }
                        }
                    }
                    log_error!("upstream peer-ID topology update failed: {}", error);
                    return true;
                }
            };
            if let Some(publication) = publication
                && let Err(error) =
                    client_cache.install_manager_publication(handles, Some(c2u_cache), publication)
            {
                drop(flow_transaction.take());
                log_error!("upstream peer-ID cache publication failed: {error}");
                context.stats.invariant_failure(true);
                context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                return true;
            }

            let consumed_session_control = event.is_session_control();
            let manager_receipt = match mark_manager_published(
                context.flow_state,
                flow_transaction.as_ref().unwrap_or_else(|| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "ACK manager publication lost its flow reservation"
                    ))
                }),
                token,
            ) {
                Ok(receipt) => receipt,
                Err(error) => {
                    drop(flow_transaction.take());
                    log_error!("reply-ID manager publication failed fatally: {error:?}");
                    context.stats.invariant_failure(true);
                    context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                    return true;
                }
            };
            let commit_result = commit_after_topology_update(
                context.flow_state,
                flow_transaction.as_ref().unwrap_or_else(|| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "ACK commit lost its flow reservation"
                    ))
                }),
                manager_receipt,
            );
            let activation = match commit_result {
                Ok(activation) => activation,
                Err(error) => {
                    drop(flow_transaction.take());
                    log_error!("reply-ID handshake commit failed fatally: {error:?}");
                    context.stats.invariant_failure(true);
                    context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                    return true;
                }
            };
            if let Err(error) = super::dispatch::activate_upstream_receive_session(
                context.cfg,
                context.flow_state,
                flow_transaction.as_ref(),
                context.upstream_side_state,
                upstream_side_cache,
                session_id,
            ) {
                if context
                    .flow_state
                    .poison_upstream_reply_id_handshake_activation(activation)
                    .is_err()
                {
                    log_error!("reply-ID handshake activation poison lost transaction ownership");
                }
                drop(flow_transaction.take());
                log_error!("reply-ID handshake activated an invalid response session: {error}");
                context.stats.invariant_failure(true);
                context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                return true;
            }
            let lease = match context
                .flow_state
                .complete_upstream_reply_id_handshake_activation(activation)
            {
                Ok(lease) => lease,
                Err(error) => {
                    drop(flow_transaction.take());
                    log_error!("reply-ID handshake activation publication failed: {error:?}");
                    context.stats.invariant_failure(true);
                    context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
                    return true;
                }
            };
            drop(flow_transaction.take());
            log_handshake_ack_matched(context.cfg, context.worker_id, handshake_trace);
            if consumed_session_control {
                log_packet_disposition(
                    context.cfg,
                    trigger_trace,
                    PacketDisposition::ConsumeSessionControl,
                );
            }
            flush_reply_id_payload(
                context,
                lease,
                handles,
                c2u_cache,
                client_side_cache,
                upstream_side_cache,
            );
            consumed_session_control
        }
        ObserveAckResult::ReserveReady { trigger_trace } => {
            drop(flow_transaction.take());
            log_packet_disposition(
                context.cfg,
                trigger_trace,
                PacketDisposition::ConsumeSessionControl,
            );
            true
        }
        ObserveAckResult::Ignored {
            reason,
            observed_ack_destination_id,
            trigger_trace,
        } => {
            drop(flow_transaction.take());
            log_handshake_ack_ignored(
                context.cfg,
                context.worker_id,
                reason,
                observed_ack_destination_id,
            );
            context.stats.handshake_stale_ack();
            log_packet_disposition(
                context.cfg,
                trigger_trace,
                if matches!(
                    reason,
                    crate::flow_state::ReplyIdHandshakeAckIgnored::AlreadyAcked { .. }
                        | crate::flow_state::ReplyIdHandshakeAckIgnored::CommitInProgress { .. }
                ) {
                    PacketDisposition::DropDuplicate
                } else {
                    PacketDisposition::ConsumeSessionControl
                },
            );
            true
        }
        ObserveAckResult::NotAck => false,
    }
}

pub(super) fn consume_reserve_reply_id_ack(
    context: &mut UpstreamWorkerContext<'_>,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
    received_at: Instant,
    handles: &SocketHandles,
) -> bool {
    match observe_reply_id_ack(
        context.cfg,
        event,
        handles,
        context.flow_state,
        received_at,
        trace,
    ) {
        ObserveAckResult::ReserveReady { trigger_trace } => {
            log_packet_disposition(
                context.cfg,
                trigger_trace,
                PacketDisposition::ConsumeSessionControl,
            );
            true
        }
        ObserveAckResult::Ignored {
            reason,
            observed_ack_destination_id,
            trigger_trace,
        } => {
            log_handshake_ack_ignored(
                context.cfg,
                context.worker_id,
                reason,
                observed_ack_destination_id,
            );
            context.stats.handshake_stale_ack();
            log_packet_disposition(
                context.cfg,
                trigger_trace,
                if matches!(
                    reason,
                    crate::flow_state::ReplyIdHandshakeAckIgnored::AlreadyAcked { .. }
                        | crate::flow_state::ReplyIdHandshakeAckIgnored::CommitInProgress { .. }
                ) {
                    PacketDisposition::DropDuplicate
                } else {
                    PacketDisposition::ConsumeSessionControl
                },
            );
            true
        }
        ObserveAckResult::Matched { .. } => {
            log_error!("reserve-local ACK unexpectedly matched the active handshake");
            context.stats.invariant_failure(false);
            context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
            true
        }
        ObserveAckResult::NotAck => false,
    }
}

#[cfg(test)]
mod tests;
