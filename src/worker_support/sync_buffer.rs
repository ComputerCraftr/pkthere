use super::PacketContext;
use super::cache::{CachedClientState, CachedSendRoute};
use crate::cli::SupportedProtocol;
use crate::diagnostics::PacketTraceId;
use crate::net::framing_shim::{ChallengeControl, IcmpTunnelControl, ReplyIdNegotiation};
use crate::net::icmp_sequence::{IcmpSequenceCache, SharedIcmpSequenceState};
use crate::net::payload::{
    BufferedPayload, C2uSessionControlDecision, PayloadEvent, classify_c2u_session_control_event,
    outbound_payload_event, send_payload,
};
use crate::net::session::handle_send_result;
use crate::net::sock_mgr::SocketHandles;
use crate::worker_support::packet_dump::{PacketDisposition, log_packet_disposition};

pub(crate) enum BufferedSyncUpdate {
    Buffered {
        buffered_trace: PacketTraceId,
        replaced_trace: Option<PacketTraceId>,
    },
    Keep,
}

pub(crate) struct SessionControlReplyContext<'a> {
    pub(crate) route: Option<&'a CachedSendRoute>,
    pub(crate) clear_new_pending_on_failure: bool,
}

fn account_pending_cleanup(
    context: &mut PacketContext<'_, '_>,
    result: Result<(), crate::runtime_support::FailureClass>,
) {
    if let Err(class) = result {
        match class {
            crate::runtime_support::FailureClass::RetryableContention
            | crate::runtime_support::FailureClass::Shutdown
            | crate::runtime_support::FailureClass::OperationFailed
            | crate::runtime_support::FailureClass::PacketRejected => {
                context.stats.topology_error(true);
            }
            crate::runtime_support::FailureClass::FatalInvariant => {
                context.stats.invariant_failure(true);
                crate::runtime_support::publish_process_fatal(format_args!(
                    "pending ICMP client cleanup lost flow authority"
                ));
            }
        }
    }
}

#[inline]
fn store_sync_payload(
    flow_state: &crate::flow_state::FlowRuntimeState,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
    received_at: std::time::Instant,
) -> BufferedSyncUpdate {
    let replaced_trace = flow_state
        .replace_sync_payload(BufferedPayload::from_event_at(
            event,
            Some(trace),
            received_at,
        ))
        .and_then(|payload| payload.trace());
    BufferedSyncUpdate::Buffered {
        buffered_trace: trace,
        replaced_trace,
    }
}

#[inline]
fn empty_icmp_reply_event(
    seq: u16,
    source_id: u16,
    header_id: u16,
    control: IcmpTunnelControl,
) -> PayloadEvent<'static> {
    PayloadEvent::session_control_v3(source_id, header_id, seq, SupportedProtocol::ICMP, control)
}

#[inline]
fn session_control_reply_for_route(
    event: &PayloadEvent<'_>,
    route: &CachedSendRoute,
) -> Option<IcmpTunnelControl> {
    let icmp = match event {
        PayloadEvent::SessionControl { icmp, .. } => icmp,
        _ => return None,
    };
    let reply_id = route.icmp_advertised_reply_id();
    match icmp.control()? {
        IcmpTunnelControl::Negotiate(negotiation) => {
            ReplyIdNegotiation::acknowledge_key_and_challenge(
                reply_id,
                negotiation.session_key(),
                negotiation.reset_challenge(),
            )
            .map(IcmpTunnelControl::NegotiateAck)
        }
        IcmpTunnelControl::ChallengeNegotiate(challenge) => ChallengeControl::new(
            reply_id,
            challenge.challenge(),
            challenge.receiver_generation(),
            challenge.rejected(),
            challenge.new_session(),
        )
        .map(IcmpTunnelControl::ChallengeAck),
        IcmpTunnelControl::GenerationAdvance(advance) => {
            Some(IcmpTunnelControl::GenerationAdvanceAck(advance))
        }
        IcmpTunnelControl::NegotiateAck(_)
        | IcmpTunnelControl::ResetRequired(_)
        | IcmpTunnelControl::ChallengeAck(_)
        | IcmpTunnelControl::GenerationAdvanceAck(_)
        | IcmpTunnelControl::SessionActivated(_) => None,
    }
}

#[inline]
pub(crate) fn handle_c2u_session_control(
    context: &mut PacketContext<'_, '_>,
    handles: &mut SocketHandles,
    client_sequence_state: &SharedIcmpSequenceState,
    default_reply_route: Option<&CachedSendRoute>,
    clear_new_pending_on_failure: bool,
    event: &PayloadEvent<'_>,
    trace: Option<PacketTraceId>,
) -> bool {
    let PacketContext { worker_id, cfg, .. } = context;
    let clear_new_pending = || -> Result<(), crate::runtime_support::FailureClass> {
        let transition = context
            .flow_state
            .try_reserve_client_flow()
            .map_err(|error| error.class())?;
        if let Some(session_id) = context
            .flow_state
            .clear_pending_icmp_client_lock_under(&transition)
            .map_err(|error| error.class())?
        {
            crate::net::icmp_sequence::unregister_receive_candidate(
                client_sequence_state,
                session_id,
            );
        }
        Ok(())
    };
    match classify_c2u_session_control_event(cfg, event) {
        Ok(C2uSessionControlDecision::Forward) | Ok(C2uSessionControlDecision::Consume) => {
            if let Some(trace) = trace {
                log_packet_disposition(cfg, trace, PacketDisposition::ConsumeSessionControl);
            }
            true
        }
        Ok(C2uSessionControlDecision::ReplyLocally) => {
            let reply_route = default_reply_route.cloned().or_else(|| {
                let dest = handles.listener.listener_flow.outbound_destination()?;
                Some(CachedClientState::build_local_session_control_reply_route(
                    handles, dest,
                ))
            });
            if let Some(reply_route) = reply_route.as_ref() {
                let sent =
                    emit_local_session_control_reply(context, handles, reply_route, event, trace);
                if !sent && clear_new_pending_on_failure {
                    let cleanup = clear_new_pending();
                    account_pending_cleanup(context, cleanup);
                }
                sent
            } else {
                log_debug_dir!(
                    cfg.debug_logs.drops,
                    worker_id,
                    true,
                    "dropping session-control reply with no locked client address"
                );
                if let Some(trace) = trace {
                    log_packet_disposition(cfg, trace, PacketDisposition::ReplyFailed);
                }
                if clear_new_pending_on_failure {
                    let cleanup = clear_new_pending();
                    account_pending_cleanup(context, cleanup);
                }
                false
            }
        }
        Err(e) => {
            let retryable_duplicate_negotiation = matches!(
                crate::net::icmp_sequence::sequence_admission_error(&e),
                Some(crate::net::icmp_sequence::SequenceAdmissionError::Duplicate)
            ) && event
                .icmp_meta()
                .is_some_and(|icmp| icmp.negotiates_reply_id());
            if retryable_duplicate_negotiation && let Some(reply_route) = default_reply_route {
                // The replay claim is retained, but an ACK send failure must
                // remain retryable without admitting user data or publishing
                // pending flow state. Work-budget accounting still bounds
                // duplicate-triggered replies.
                return emit_local_session_control_reply(
                    context,
                    handles,
                    reply_route,
                    event,
                    trace,
                );
            }
            log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                true,
                "classify_c2u_session_control_event error: {}",
                e
            );
            if let Some(trace) = trace {
                log_packet_disposition(cfg, trace, PacketDisposition::DropDuplicate);
            }
            if clear_new_pending_on_failure {
                let cleanup = clear_new_pending();
                account_pending_cleanup(context, cleanup);
            }
            false
        }
    }
}

#[inline]
fn emit_local_session_control_reply(
    context: &mut PacketContext<'_, '_>,
    handles: &mut SocketHandles,
    route: &CachedSendRoute,
    event: &PayloadEvent<'_>,
    trace: Option<PacketTraceId>,
) -> bool {
    let seq = match event {
        PayloadEvent::SessionControl { icmp, .. } => icmp.seq(),
        _ => return false,
    };
    let source_id = route.icmp_source_id();
    let Some(control) = session_control_reply_for_route(event, route) else {
        return false;
    };
    let reply_event = empty_icmp_reply_event(seq, source_id, route.icmp_header_id, control);
    emit_local_control_event(context, handles, route, &reply_event, None, trace)
}

pub(crate) fn emit_local_reset_required(
    context: &mut PacketContext<'_, '_>,
    handles: &mut SocketHandles,
    route: &CachedSendRoute,
    reset: crate::net::framing_shim::ResetRequired,
    sequence: u16,
    trace: Option<PacketTraceId>,
) -> bool {
    let event = PayloadEvent::session_reset_required(
        route.icmp_source_id(),
        route.icmp_header_id,
        sequence,
        SupportedProtocol::ICMP,
        reset,
    );
    emit_local_control_event(context, handles, route, &event, None, trace)
}

pub(crate) fn emit_local_session_activated(
    context: &mut PacketContext<'_, '_>,
    handles: &mut SocketHandles,
    route: &CachedSendRoute,
    activated: crate::net::framing_shim::SessionActivated,
    trace: Option<PacketTraceId>,
) -> bool {
    let sequence = activated.accepted_sequence();
    let event = PayloadEvent::session_control_v3(
        route.icmp_source_id(),
        route.icmp_header_id,
        sequence,
        SupportedProtocol::ICMP,
        IcmpTunnelControl::SessionActivated(activated),
    );
    emit_local_control_event(context, handles, route, &event, None, trace)
}

fn emit_local_control_event(
    context: &mut PacketContext<'_, '_>,
    handles: &mut SocketHandles,
    route: &CachedSendRoute,
    reply_event: &PayloadEvent<'_>,
    negotiation: Option<ReplyIdNegotiation>,
    trace: Option<PacketTraceId>,
) -> bool {
    let PacketContext { worker_id, cfg, .. } = context;
    let Some(meta) = reply_event.icmp_meta() else {
        log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            false,
            "session-control reply is missing ICMP metadata"
        );
        return false;
    };
    let seq = meta.seq();
    let source_id = route.icmp_source_id();
    let outbound = match outbound_payload_event(
        reply_event,
        route.icmp_header_id,
        false,
        Some(seq),
        source_id,
        Some(meta.session_id()),
        negotiation,
    ) {
        Ok(outbound) => outbound,
        Err(e) => {
            log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                false,
                "session-control reply build error: {}",
                e
            );
            if let Some(trace) = trace {
                log_packet_disposition(cfg, trace, PacketDisposition::ReplyFailed);
            }
            return false;
        }
    };
    let attempted_at = std::time::Instant::now();
    let send_res = send_payload(
        &handles.client_sock,
        &route.dest_sa,
        handles.listener.policy.send_policy,
        route.source_ip,
        &outbound,
    );
    let completed_at = std::time::Instant::now();
    matches!(
        handle_send_result(
            context,
            false,
            reply_event,
            crate::net::session::SendOutcome {
                result: &send_res,
                attempted_at,
                completed_at,
                account_success: true,
                destination: &route.dest_sa,
                trace,
                trace_kind: crate::net::session::SendTraceKind::ReplySessionControl,
            },
        ),
        crate::net::session::HandledSendOutcome::Sent { .. }
    )
}

#[inline]
pub(crate) fn buffer_sync_event(
    context: &mut PacketContext<'_, '_>,
    handles: &mut SocketHandles,
    client_sequence: (&SharedIcmpSequenceState, &mut IcmpSequenceCache),
    reply_context: SessionControlReplyContext<'_>,
    event: PayloadEvent<'_>,
    trace: PacketTraceId,
) -> BufferedSyncUpdate {
    let (client_side_state, client_side_cache) = client_sequence;
    match event {
        PayloadEvent::UserPayload { .. } => {
            if let Err(error) = crate::net::payload::classify_c2u_data_or_cadence_event(
                &event,
                client_side_state,
                client_side_cache,
            ) {
                log_packet_disposition(
                    context.cfg,
                    trace,
                    super::record_sequence_rejection(context.stats, true, &error),
                );
                return BufferedSyncUpdate::Keep;
            }
            super::record_user_payload_route(context, super::UserPayloadRoute::BufferSyncPayload);
            store_sync_payload(context.flow_state, &event, trace, context.t_event)
        }
        PayloadEvent::SessionControl { .. } => {
            handle_c2u_session_control(
                context,
                handles,
                client_side_state,
                reply_context.route,
                reply_context.clear_new_pending_on_failure,
                &event,
                Some(trace),
            );
            BufferedSyncUpdate::Keep
        }
        PayloadEvent::CadencePacket { .. } => {
            if let Err(error) = crate::net::payload::classify_c2u_data_or_cadence_event(
                &event,
                client_side_state,
                client_side_cache,
            ) {
                log_packet_disposition(
                    context.cfg,
                    trace,
                    super::record_sequence_rejection(context.stats, true, &error),
                );
                return BufferedSyncUpdate::Keep;
            }
            log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeCadence);
            BufferedSyncUpdate::Keep
        }
    }
}

#[cfg(all(test, not(miri)))]
mod tests;
