pub(super) use super::client::ClientWorkerContext;
pub(super) use super::client_lock::{
    accept_pending_negotiation, prepare_client_lock, publish_client_lock_with_transaction,
    release_prepared_client_lock,
};
use super::client_process::ClientPacketProcessor;
use super::dispatch::UserPayloadSendDecision;
pub(super) use super::packet_admission::AdmittedWirePacket;
pub(super) use super::{
    BufferedSyncUpdate, CLIENT_TO_UPSTREAM as C2U, CachedClientState, PacketContext,
    PacketDisposition, PacketTraceId, SequenceContext, SessionControlReplyContext,
    buffer_sync_event, handle_c2u_session_control, log_packet_disposition,
    send_payload_event_now_stable, send_user_payload_event,
};
use crate::cli::SupportedProtocol;
pub(super) use crate::flow_state::ClientFlowReservation;
pub(super) use crate::net::icmp_sequence::IcmpSequenceCache;
use crate::net::payload::PayloadEvent;
pub(super) use crate::net::sock_mgr::{ManagerError, SocketHandles};
use crate::stats::StatsSink;
pub(super) use std::time::Instant;

pub(super) enum C2uDispatchOutcome {
    Complete,
    Rekey(crate::net::icmp_sequence::RekeyRequired),
    AssociationStale(crate::net::managed_socket::AssociationStale),
    BeginHandshake(crate::net::framing_shim::ReplyIdNegotiation),
    DeferredControl(crate::flow_state::DeferredPeerControl),
}

fn fail_fatal_dispatch(
    context: &mut ClientWorkerContext<'_>,
    trace: PacketTraceId,
    operation: &str,
    error: &std::io::Error,
) {
    log_error_dir!(
        context.worker_id,
        C2U,
        "fatal {operation} invariant failure for packet {}: {}",
        trace.packet_id,
        error
    );
    context.stats.invariant_failure(C2U);
    context.exit_code_set.store(
        crate::runtime_support::FATAL_EXIT,
        std::sync::atomic::Ordering::Release,
    );
    log_packet_disposition(context.cfg, trace, PacketDisposition::SendFailed);
}

fn record_sync_buffer_update(cfg: &crate::cli::RuntimeConfig, update: BufferedSyncUpdate) {
    if let BufferedSyncUpdate::Buffered {
        buffered_trace,
        replaced_trace: Some(replaced_trace),
    } = update
        && buffered_trace != replaced_trace
    {
        log_packet_disposition(cfg, replaced_trace, PacketDisposition::DropSyncReplaced);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_client_reset_challenge(
    context: &mut ClientWorkerContext<'_>,
    flow_transaction: &mut Option<ClientFlowReservation<'_>>,
    handles: &mut SocketHandles,
    route: &crate::worker_support::CachedSendRoute,
    peer_flow: crate::flow_key::ClientFlowKey,
    rejected: crate::net::framing_shim::RejectedFrameEvidence,
    trace: PacketTraceId,
    received_at: Instant,
) {
    let response_bytes = crate::net::framing_shim::ICMP_TUNNEL_EXPLICIT_RESET_REQUIRED_LEN as u32;
    if !context
        .flow_state
        .reserve_client_reset_response(peer_flow, received_at, response_bytes)
    {
        return;
    }
    let expires_at =
        received_at + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs);
    match context.flow_state.issue_client_reset_challenge(
        peer_flow,
        rejected,
        received_at,
        expires_at,
    ) {
        Ok(
            crate::flow_state::ResetChallengeIssue::Created(challenge)
            | crate::flow_state::ResetChallengeIssue::Reused(challenge),
        ) => {
            let reset = crate::net::framing_shim::ResetRequired::for_evidence(
                rejected,
                challenge.receiver_generation,
                challenge.challenge,
            );
            drop(flow_transaction.take());
            super::sync_buffer::emit_local_reset_required(
                &mut PacketContext::new(
                    context.worker_id,
                    context.t_start,
                    received_at,
                    context.cfg,
                    context.stats,
                    context.flow_state,
                ),
                handles,
                route,
                reset,
                rejected.sequence(),
                Some(trace),
            );
        }
        Ok(crate::flow_state::ResetChallengeIssue::DifferentConflictPending) => {}
        Err(error) => {
            log_error_dir!(
                context.worker_id,
                C2U,
                "fatal ICMP reset-challenge generation failure: {}",
                error
            );
            context.stats.invariant_failure(C2U);
            context.exit_code_set.store(
                crate::runtime_support::FATAL_EXIT,
                std::sync::atomic::Ordering::Release,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_c2u_event(
    context: &mut ClientWorkerContext<'_>,
    handles: &mut SocketHandles,
    cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
    received_at: Instant,
    sequence_already_admitted: bool,
    permit: crate::worker_support::StableForwardPermit<'_>,
) -> C2uDispatchOutcome {
    let packet_context = &mut PacketContext::new(
        context.worker_id,
        context.t_start,
        received_at,
        context.cfg,
        context.stats,
        context.flow_state,
    )
    .with_flow_snapshot(permit.snapshot());
    let sequences = SequenceContext::new(
        context.client_side_state,
        client_side_cache,
        context.upstream_side_state,
        upstream_side_cache,
    );
    match event {
        PayloadEvent::UserPayload { .. } => {
            if !sequence_already_admitted
                && let Err(error) = crate::net::payload::classify_c2u_data_or_cadence_event(
                    event,
                    sequences.client_state,
                    sequences.client_cache,
                )
            {
                drop(permit);
                log_packet_disposition(
                    context.cfg,
                    trace,
                    super::record_sequence_rejection(context.stats, C2U, &error),
                );
                return C2uDispatchOutcome::Complete;
            }
            match send_user_payload_event(
                packet_context,
                event,
                handles,
                cache,
                sequences,
                Some(trace),
                permit,
            ) {
                Ok(UserPayloadSendDecision::Sent {
                    deferred_control: Some(control),
                    ..
                }) => return C2uDispatchOutcome::DeferredControl(control),
                Ok(UserPayloadSendDecision::Sent {
                    deferred_control: None,
                    ..
                }) => {}
                Ok(UserPayloadSendDecision::BeginHandshake(negotiation)) => {
                    return C2uDispatchOutcome::BeginHandshake(negotiation);
                }
                Err(error) => {
                    if let Some(rekey) = crate::net::icmp_sequence::rekey_required(&error) {
                        return C2uDispatchOutcome::Rekey(rekey);
                    }
                    if let Some(stale) =
                        crate::net::managed_socket::AssociationStale::from_io(&error)
                    {
                        return C2uDispatchOutcome::AssociationStale(stale);
                    }
                    fail_fatal_dispatch(context, trace, "outbound payload", &error);
                }
            }
        }
        PayloadEvent::SessionControl { dst_proto, .. } => {
            let should_forward = *dst_proto == context.cfg.upstream_proto
                && *dst_proto == SupportedProtocol::ICMP
                && context.cfg.is_icmp_sync_enabled();
            if should_forward {
                if let Err(error) = send_payload_event_now_stable(
                    packet_context,
                    event,
                    handles,
                    cache,
                    sequences,
                    Some(trace),
                    permit,
                ) {
                    fail_fatal_dispatch(context, trace, "session-control forward", &error);
                }
            } else {
                drop(permit);
                handle_c2u_session_control(
                    packet_context,
                    handles,
                    context.client_side_state,
                    cache.session_control_reply_route.as_ref(),
                    false,
                    event,
                    Some(trace),
                );
            }
        }
        PayloadEvent::CadencePacket { .. } => {
            if !sequence_already_admitted
                && let Err(error) = crate::net::payload::classify_c2u_data_or_cadence_event(
                    event,
                    sequences.client_state,
                    sequences.client_cache,
                )
            {
                drop(permit);
                log_packet_disposition(
                    context.cfg,
                    trace,
                    super::record_sequence_rejection(context.stats, C2U, &error),
                );
                return C2uDispatchOutcome::Complete;
            }
            drop(permit);
            log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeCadence);
        }
    }
    C2uDispatchOutcome::Complete
}

pub(super) fn process_sync_packet(
    context: &mut ClientWorkerContext<'_>,
    mutation_authority: crate::worker_support::ReceiveMutationAuthority<'_>,
    handles: &mut SocketHandles,
    cache: &CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    received_at: Instant,
    admitted: AdmittedWirePacket<'_>,
) {
    let flow_read = mutation_authority.into_flow();
    let Some(trace) = admitted.trace else {
        context.stats.invariant_failure(C2U);
        return;
    };
    drop(flow_read);
    let flow_transaction = match context.flow_state.try_reserve_client_flow() {
        Ok(transaction) => transaction,
        Err(error) => {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "sync packet transition reservation failed: {error}"
                ));
                context.stats.invariant_failure(C2U);
            }
            return;
        }
    };
    let pending_reply = match accept_pending_negotiation(
        context,
        &flow_transaction,
        admitted.pending_negotiation(),
        trace,
        admitted.event.icmp_meta().map_or(0, |icmp| icmp.seq()),
        received_at,
    ) {
        Ok(route) => route,
        Err(()) => return,
    };
    let is_control = matches!(admitted.event, PayloadEvent::SessionControl { .. });
    if is_control {
        drop(flow_transaction);
    }
    let update = buffer_sync_event(
        &mut PacketContext::new(
            context.worker_id,
            context.t_start,
            received_at,
            context.cfg,
            context.stats,
            context.flow_state,
        ),
        handles,
        (context.client_side_state, client_side_cache),
        SessionControlReplyContext {
            route: pending_reply
                .as_ref()
                .map(|(route, _)| route)
                .or(cache.session_control_reply_route.as_ref()),
            clear_new_pending_on_failure: pending_reply
                .as_ref()
                .is_some_and(|(_, newly_started)| *newly_started),
        },
        admitted.event,
        trace,
    );
    record_sync_buffer_update(context.cfg, update);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn process_client_packet<'context>(
    context: &mut ClientWorkerContext<'context>,
    mutation_authority: crate::worker_support::ReceiveMutationAuthority<'context>,
    handles: &mut SocketHandles,
    cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
    was_locked: &mut bool,
    received_at: Instant,
    flow_snapshot: crate::flow_state::PacketFlowSnapshot,
    admitted: AdmittedWirePacket<'_>,
) -> Result<(), ManagerError> {
    ClientPacketProcessor::new(
        context,
        mutation_authority,
        handles,
        cache,
        client_side_cache,
        upstream_side_cache,
        was_locked,
        received_at,
        flow_snapshot,
    )
    .process(admitted)
}
