use super::handshake_trace::{HandshakeAckMatched, log_handshake_begin};
use super::{CachedClientState, PacketContext, SequenceContext};
use crate::cli::RuntimeConfig;
use crate::diagnostics::PacketTraceId;
use crate::endpoint::LogicalEndpoint;
use crate::flow_state::ReplyIdHandshakeAckIgnored;
use crate::flow_state::{FlowRuntimeState, ReplyIdHandshakeAck, ReplyIdHandshakeCommitToken};
use crate::net::framing_shim::ReplyIdNegotiation;
use crate::net::icmp_sequence::{IcmpSequenceCache, SharedIcmpSequenceState};
use crate::net::payload::{
    BufferedPayload, PayloadEvent, prepare_outbound_payload_event, reply_id_negotiation_for_c2u,
    send_payload_with_lease,
};
use crate::net::session::HandledSendOutcome;
use crate::net::session::handle_send_result;
use crate::net::sock_mgr::SocketHandles;
use std::io;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserPayloadRoute {
    ForwardNow,
    BufferFirstHandshakePayload,
    BufferSyncPayload,
    DropHandshakePending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserPayloadSendDecision {
    Sent {
        outcome: HandledSendOutcome,
        deferred_control: Option<crate::flow_state::DeferredPeerControl>,
    },
    BeginHandshake(ReplyIdNegotiation),
}

struct UpstreamDataPayloadSend<'payload> {
    destination: &'payload socket2::SockAddr,
    policy: pkthere_socket_policy::SocketSendPolicy,
    source_ip: Option<std::net::IpAddr>,
    outbound: &'payload crate::net::payload::OutboundPayloadEvent<'payload>,
    audit_stable_pipeline: bool,
}

impl<Flow>
    crate::worker_support::context::StableSendTransaction<
        Flow,
        crate::net::managed_socket::ManagedSendLease<'_>,
        crate::net::icmp_sequence::OutboundDataProtocol<'_>,
    > for UpstreamDataPayloadSend<'_>
{
    type SendResult = io::Result<crate::net::managed_socket::ManagedSendResult>;
    type Output = (
        Self::SendResult,
        Result<
            Option<crate::flow_state::DeferredPeerControl>,
            crate::net::icmp_sequence::RekeyRequired,
        >,
    );

    fn send(
        &mut self,
        _flow: &mut Flow,
        send_lease: &crate::net::managed_socket::ManagedSendLease<'_>,
        _protocol: &mut crate::net::icmp_sequence::OutboundDataProtocol<'_>,
    ) -> Self::SendResult {
        if self.audit_stable_pipeline {
            super::pipeline_audit::checkpoint(true, super::PipelineStage::BeforeSend);
        }
        let result = send_payload_with_lease(
            send_lease,
            self.destination,
            self.policy,
            self.source_ip,
            self.outbound,
        );
        if self.audit_stable_pipeline {
            super::pipeline_audit::checkpoint(true, super::PipelineStage::AfterSend);
        }
        result
    }

    fn complete(
        self,
        _flow: &mut Flow,
        _socket: &crate::net::managed_socket::ManagedSendLease<'_>,
        protocol: &mut crate::net::icmp_sequence::OutboundDataProtocol<'_>,
        send_result: Self::SendResult,
    ) -> Self::Output {
        let deferred = protocol.complete_data(send_result.is_ok());
        (send_result, deferred)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncSessionTransition {
    Exhausted {
        old_session_id: crate::net::framing_shim::SessionId,
    },
    BeginHandshake {
        negotiation: ReplyIdNegotiation,
    },
}

pub(crate) enum SyncSendAttempt {
    Complete(PayloadSendResult),
    TransitionRequired(SyncSessionTransition),
}

#[inline]
pub(super) fn is_retryable_outbound_session_race(error: &io::Error) -> bool {
    crate::net::icmp_sequence::rekey_required(error).is_some()
}

pub(crate) struct PayloadSendResult {
    pub(crate) outcome: HandledSendOutcome,
    pub(crate) attempted_at: Instant,
    pub(crate) completed_at: Instant,
    pub(crate) retained_recovery_payload: bool,
    pub(crate) deferred_control: Option<crate::flow_state::DeferredPeerControl>,
}

#[inline]
pub(super) fn release_pre_sequence_send_authorities(
    send_lease: crate::net::managed_socket::ManagedSendLease<'_>,
    stable_permit: Option<crate::worker_support::StableForwardPermit<'_>>,
) {
    drop(send_lease);
    drop(stable_permit);
}

impl PayloadSendResult {
    #[inline]
    const fn transferred_payload_ownership(&self) -> bool {
        self.retained_recovery_payload || matches!(self.outcome, HandledSendOutcome::Sent { .. })
    }
}
impl UserPayloadRoute {
    #[inline]
    const fn records_activity(self) -> bool {
        matches!(
            self,
            Self::ForwardNow | Self::BufferFirstHandshakePayload | Self::BufferSyncPayload
        )
    }
}

#[inline]
pub(crate) fn record_user_payload_route(
    context: &mut PacketContext<'_, '_>,
    route: UserPayloadRoute,
) {
    if route.records_activity() {
        context.flow_state.record_activity_for_lane(
            context.flow_lane,
            context.t_start,
            context.t_event,
        );
    }
}

pub(crate) fn apply_deferred_upstream_control(
    context: &mut PacketContext<'_, '_>,
    handles: &SocketHandles,
    cache: &CachedClientState,
    upstream_state: &SharedIcmpSequenceState,
    control: crate::flow_state::DeferredPeerControl,
) -> io::Result<()> {
    match control {
        crate::flow_state::DeferredPeerControl::SessionActivated {
            control,
            observed_at,
        } => context
            .flow_state
            .observe_upstream_session_activated(
                control,
                observed_at,
                crate::net::icmp_sequence::DataSequenceEvidenceState::Sent,
            )
            .map(|_| ())
            .map_err(|_| io::Error::other("deferred ICMP activation became stale")),
        crate::flow_state::DeferredPeerControl::ResetRequired {
            control: reset,
            observed_at,
        } => {
            let expected_ack_destination_id =
                cache.expected_upstream_ack_destination_id(handles)?;
            let flow_transaction =
                context
                    .flow_state
                    .try_reserve_client_flow()
                    .map_err(|error| {
                        super::reservation_io_error("reserve deferred ICMP reset recovery", error)
                    })?;
            let recovery = context
                .flow_state
                .recover_upstream_session_under(
                    &flow_transaction,
                    crate::flow_state::UpstreamRecoveryRequest {
                        sequences: upstream_state,
                        reset,
                        expected_ack_destination_id,
                        observed_at,
                        absolute_deadline: observed_at
                            + std::time::Duration::from_secs(
                                context.cfg.icmp_handshake_timeout_secs,
                            ),
                        started_s: observed_at
                            .saturating_duration_since(context.t_start)
                            .as_secs()
                            .max(1),
                    },
                )
                .map_err(|error| {
                    super::flow_mutation_io_error("deferred ICMP reset recovery failed", error)
                })?;
            if let crate::flow_state::UpstreamSessionRecovery::Recovered {
                retired_sessions, ..
            } = recovery
            {
                upstream_state.retire_outbound_sessions(&retired_sessions);
            }
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(crate) enum ObserveAckResult {
    Matched {
        token: ReplyIdHandshakeCommitToken,
        peer_source_id: u16,
        peer_reply_id: u16,
        trigger_trace: PacketTraceId,
        handshake_trace: HandshakeAckMatched,
    },
    ReserveReady {
        trigger_trace: PacketTraceId,
    },
    Ignored {
        reason: ReplyIdHandshakeAckIgnored,
        observed_ack_destination_id: u16,
        trigger_trace: PacketTraceId,
    },
    NotAck,
}

mod retry;
use retry::{explicit_reply_id_ack, reflected_kernel_echo_negotiation_matches};
pub(crate) use retry::{retry_due_upstream_negotiation, retry_due_upstream_recovery_payload};
#[inline]
pub(crate) fn send_user_payload_event(
    context: &mut PacketContext<'_, '_>,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    sequences: SequenceContext<'_>,
    trace: Option<PacketTraceId>,
    permit: crate::worker_support::StableForwardPermit<'_>,
) -> io::Result<UserPayloadSendDecision> {
    send_user_payload_event_once(context, event, handles, cache, sequences, trace, permit)
}

#[inline]
fn send_user_payload_event_once(
    context: &mut PacketContext<'_, '_>,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    sequences: SequenceContext<'_>,
    trace: Option<PacketTraceId>,
    permit: crate::worker_support::StableForwardPermit<'_>,
) -> io::Result<UserPayloadSendDecision> {
    let local_reply_id = handles.upstream.upstream_local_filter.id();
    let upstream_reply_id_acked = permit.snapshot().upstream_reply_id_acked;
    let reply_id_negotiation =
        reply_id_negotiation_for_c2u(event, upstream_reply_id_acked, local_reply_id)?;
    if let Some(reply_id_negotiation) = reply_id_negotiation
        && reply_id_negotiation.is_negotiate()
    {
        return Ok(UserPayloadSendDecision::BeginHandshake(
            reply_id_negotiation,
        ));
    }
    record_user_payload_route(context, UserPayloadRoute::ForwardNow);
    send_payload_event_now_with_accounting_inner(
        context,
        event,
        handles,
        cache,
        (sequences.upstream_state, sequences.upstream_cache),
        trace,
        true,
        true,
        None,
        None,
        Some(permit),
        true,
    )
    .map(|result| UserPayloadSendDecision::Sent {
        outcome: result.outcome,
        deferred_control: result.deferred_control,
    })
}

#[inline]
pub(crate) fn send_payload_event_now_stable(
    context: &mut PacketContext<'_, '_>,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    sequences: SequenceContext<'_>,
    trace: Option<PacketTraceId>,
    permit: crate::worker_support::StableForwardPermit<'_>,
) -> io::Result<HandledSendOutcome> {
    send_payload_event_now_with_accounting_inner(
        context,
        event,
        handles,
        cache,
        (sequences.upstream_state, sequences.upstream_cache),
        trace,
        true,
        true,
        None,
        None,
        Some(permit),
        true,
    )
    .map(|result| result.outcome)
}

#[derive(Clone, Copy)]
pub(crate) struct SendAccounting {
    pub(crate) success: bool,
    pub(crate) activation_recovery: bool,
}

#[derive(Clone, Copy)]
pub(super) struct StableSendAccounting {
    pub(super) trace: Option<PacketTraceId>,
    pub(super) accounting: SendAccounting,
}

#[inline]
pub(super) fn send_payload_event_now_with_accounting_stable(
    context: &mut PacketContext<'_, '_>,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    sequences: SequenceContext<'_>,
    send_accounting: StableSendAccounting,
    stable_permit: crate::worker_support::StableForwardPermit<'_>,
) -> io::Result<PayloadSendResult> {
    send_payload_event_now_with_accounting_inner(
        context,
        event,
        handles,
        cache,
        (sequences.upstream_state, sequences.upstream_cache),
        send_accounting.trace,
        send_accounting.accounting.success,
        send_accounting.accounting.activation_recovery,
        None,
        None,
        Some(stable_permit),
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn send_payload_event_now_with_accounting_inner(
    context: &mut PacketContext<'_, '_>,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    upstream_sequence: (&SharedIcmpSequenceState, &mut IcmpSequenceCache),
    trace: Option<PacketTraceId>,
    account_success: bool,
    retain_recovery: bool,
    recovery_payload_source: Option<&BufferedPayload>,
    recovery_token: Option<&crate::flow_state::RecoveryPayloadSendToken>,
    mut stable_permit: Option<crate::worker_support::StableForwardPermit<'_>>,
    audit_same_thread_pipeline: bool,
) -> io::Result<PayloadSendResult> {
    const C2U: bool = true;
    if let Some(permit) = stable_permit.as_ref() {
        permit.validate(context.flow_state, handles)?;
    }
    let source_id = cache.route.icmp_source_id();
    let permit_snapshot = stable_permit
        .as_ref()
        .map(crate::worker_support::StableForwardPermit::snapshot);
    let upstream_reply_id_acked = permit_snapshot
        .map(|snapshot| snapshot.upstream_reply_id_acked)
        .or_else(|| {
            context
                .flow_snapshot
                .map(|snapshot| snapshot.upstream_reply_id_acked)
        })
        .unwrap_or_else(|| context.flow_state.upstream_reply_id_acked());
    let reply_id_negotiation = reply_id_negotiation_for_c2u(
        event,
        upstream_reply_id_acked,
        handles.upstream.upstream_local_filter.id(),
    )?;
    let upstream_session_id = match permit_snapshot {
        Some(snapshot) => snapshot.upstream_transmit_session_id,
        None => context.flow_snapshot.map_or_else(
            || context.flow_state.upstream_session_id(),
            |snapshot| snapshot.upstream_transmit_session_id,
        ),
    };
    let session_id =
        outbound_upstream_session_id(upstream_session_id, event, reply_id_negotiation)?;
    let prepared_outbound = prepare_outbound_payload_event(
        event,
        cache.route.icmp_header_id,
        C2U,
        source_id,
        session_id,
        reply_id_negotiation,
    )?;
    let (upstream_state, upstream_cache) = upstream_sequence;
    let prepared_session = session_id
        .map(|session_id| {
            crate::net::icmp_sequence::claim_prepared_outbound_session(
                upstream_state,
                upstream_cache,
                session_id,
            )
        })
        .transpose()
        .map_err(io::Error::other)?;
    let recovery_already_claimed = prepared_session
        .as_ref()
        .map(
            crate::net::icmp_sequence::PreparedOutboundSession::activation_recovery_already_claimed,
        )
        .transpose()
        .map_err(io::Error::other)?
        .unwrap_or(false);
    let prepare_recovery_payload = retain_recovery
        && recovery_token.is_none()
        && event.is_user_payload()
        && session_id.is_some()
        && !recovery_already_claimed;
    // Generated cadence/control traffic owns a stable flow permit for safety,
    // but it is not a received user packet and therefore must not inflate the
    // receive-to-send pipeline evidence. The complete pipeline counters track
    // only user payloads with one originating receive.
    let audit_stable_pipeline =
        audit_same_thread_pipeline && stable_permit.is_some() && event.is_user_payload();
    let super::cache::CachedSendLease {
        socket: send_lease,
        destination,
        source_ip: send_source_ip,
        ..
    } = cache.acquire_prepared_send(handles)?;
    if audit_stable_pipeline {
        super::pipeline_audit::checkpoint(C2U, super::PipelineStage::DestinationSocketAcquired);
    }
    if let Some(permit) = stable_permit.as_ref() {
        permit.validate(context.flow_state, handles)?;
    }
    let tracked_data_sequence = event.is_user_payload() || event.is_cadence_packet();
    let claim_activation_recovery = retain_recovery
        && recovery_token.is_none()
        && event.is_user_payload()
        && prepared_session.is_some();
    let protocol_reservation = crate::net::icmp_sequence::outbound_data_reservation(
        prepared_session,
        tracked_data_sequence,
        claim_activation_recovery,
    );
    let stable_send = crate::worker_support::StableSendCore::new(stable_permit.take())
        .acquire_socket(send_lease)
        .reserve_protocol(protocol_reservation)
        .map_err(io::Error::other)?;
    let icmp_sequence = stable_send.protocol().sequence();
    if audit_stable_pipeline {
        super::pipeline_audit::checkpoint(C2U, super::PipelineStage::SequenceReserved);
    }
    let outbound = match prepared_outbound.finish(icmp_sequence) {
        Ok(outbound) => outbound,
        Err(_) => {
            drop(stable_send);
            return Err(io::Error::other(
                "prepared ICMP payload lost its reserved sequence",
            ));
        }
    };
    let activation_recovery_claimed = stable_send.protocol().activation_recovery_claimed();
    let attempted_at = Instant::now();
    let (send_res, deferred_control_result) = stable_send.perform(UpstreamDataPayloadSend {
        destination,
        policy: handles.upstream.policy.send_policy,
        source_ip: send_source_ip,
        outbound: &outbound,
        audit_stable_pipeline,
    });
    let association_stale = send_res
        .as_ref()
        .err()
        .and_then(crate::net::managed_socket::AssociationStale::from_io);
    let completed_at = Instant::now();
    let deferred_control = match deferred_control_result {
        Ok(control) => control,
        Err(_) => return Err(io::Error::other("ICMP data sequence lease became stale")),
    };
    if let (Some(token), Some(sequence)) = (recovery_token, icmp_sequence) {
        context
            .flow_state
            .prepare_upstream_recovery_payload_send(token, sequence)
            .map_err(|_| io::Error::other("ICMP recovery payload send lease became stale"))?;
    }
    // Buffering owns payload bytes and may allocate. StableSendCore has consumed
    // the flow, socket, and protocol authorities before this cold recovery work.
    let prepared_recovery_payload =
        (prepare_recovery_payload && activation_recovery_claimed).then(|| {
            recovery_payload_source.map_or_else(
                || BufferedPayload::from_event_at(event, trace, context.t_event),
                Clone::clone,
            )
        });
    let retained_recovery = if activation_recovery_claimed
        && let (Some(session_id), Some(sequence)) = (session_id, icmp_sequence)
    {
        let deadline = context.t_event
            + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs);
        let retention = match prepared_recovery_payload {
            Some(payload) => context
                .flow_state
                .retain_owned_upstream_recovery_payload(session_id, sequence, payload, deadline),
            None => crate::flow_state::RecoveryPayloadRetention::Occupied,
        };
        retention.owns_recovery()
    } else {
        false
    };
    let outcome = handle_send_result(
        context,
        C2U,
        event,
        crate::net::session::SendOutcome {
            result: &send_res,
            attempted_at,
            completed_at,
            account_success,
            destination,
            trace,
            trace_kind: crate::net::session::SendTraceKind::Forward,
        },
    );
    if retained_recovery && let (Some(session_id), Some(sequence)) = (session_id, icmp_sequence) {
        context
            .flow_state
            .record_upstream_recovery_send_result(
                session_id,
                sequence,
                matches!(outcome, HandledSendOutcome::Sent { .. }),
                completed_at,
            )
            .map_err(|_| io::Error::other("ICMP recovery payload state became stale"))?;
    }
    if let Some(stale) = association_stale {
        return Err(io::Error::new(io::ErrorKind::WouldBlock, stale));
    }
    Ok(PayloadSendResult {
        outcome,
        attempted_at,
        completed_at,
        retained_recovery_payload: retained_recovery,
        deferred_control,
    })
}

#[inline]
fn outbound_upstream_session_id(
    active_session: Option<crate::net::framing_shim::SessionId>,
    event: &PayloadEvent<'_>,
    negotiation: Option<ReplyIdNegotiation>,
) -> io::Result<Option<crate::net::framing_shim::SessionId>> {
    if event.dst_proto() != crate::cli::SupportedProtocol::ICMP {
        return Ok(None);
    }
    negotiation
        .map(ReplyIdNegotiation::instance)
        .or(active_session)
        .map(Some)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ICMP destination leg has no negotiated transmit session",
            )
        })
}

#[inline]
pub(crate) fn send_sync_payload_or_cadence(
    context: &mut PacketContext<'_, '_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    upstream_sequence: (&SharedIcmpSequenceState, &mut IcmpSequenceCache),
    owned_buffered_payload: &mut Option<BufferedPayload>,
    stable_permit: crate::worker_support::StableForwardPermit<'_>,
) -> io::Result<SyncSendAttempt> {
    const C2U: bool = true;
    let flow_snapshot = context
        .flow_snapshot
        .ok_or_else(|| io::Error::other("synchronized send has no stable flow snapshot"))?;
    if owned_buffered_payload.is_none() && !flow_snapshot.upstream_reply_id_acked {
        return Ok(SyncSendAttempt::Complete(deferred_payload_send_result(
            context.t_event,
        )));
    }
    let worker_id = context.worker_id;
    let cfg = context.cfg;
    let mut send_context = PacketContext {
        worker_id,
        t_start: context.t_start,
        t_event: owned_buffered_payload
            .as_ref()
            .map(BufferedPayload::received_at)
            .unwrap_or(context.t_event),
        cfg,
        stats: &mut *context.stats,
        flow_state: context.flow_state,
        flow_lane: context.flow_lane,
        flow_snapshot: context.flow_snapshot,
    };
    let (upstream_side_state, upstream_side_cache) = upstream_sequence;
    let trace = owned_buffered_payload
        .as_ref()
        .and_then(BufferedPayload::trace);

    if let Some(old_session_id) = flow_snapshot.upstream_transmit_session_id
        && crate::net::icmp_sequence::outbound_session_requires_rekey(
            upstream_side_state,
            upstream_side_cache,
            old_session_id,
        )
    {
        return Ok(SyncSendAttempt::TransitionRequired(
            SyncSessionTransition::Exhausted { old_session_id },
        ));
    }

    let synthetic_event;
    let event = if let Some(payload) = owned_buffered_payload.as_ref() {
        payload.as_event()
    } else {
        let Some(ident) = handles
            .listener
            .listener_flow
            .outbound_destination()
            .map(LogicalEndpoint::id)
        else {
            log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                C2U,
                "synthetic cadence packet error: missing listener outbound destination"
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "synthetic cadence packet has no listener destination identity",
            ));
        };
        let Some(session_id) = flow_snapshot.upstream_transmit_session_id else {
            return Ok(SyncSendAttempt::Complete(deferred_payload_send_result(
                context.t_event,
            )));
        };
        synthetic_event = PayloadEvent::cadence_packet(ident, 0, session_id);
        synthetic_event
    };

    let reply_id_negotiation = reply_id_negotiation_for_c2u(
        &event,
        flow_snapshot.upstream_reply_id_acked,
        handles.upstream.upstream_local_filter.id(),
    )?;
    if let Some(negotiation) = reply_id_negotiation
        && negotiation.is_negotiate()
    {
        return Ok(SyncSendAttempt::TransitionRequired(
            SyncSessionTransition::BeginHandshake { negotiation },
        ));
    }
    let result = send_payload_event_now_with_accounting_inner(
        &mut send_context,
        &event,
        handles,
        cache,
        (upstream_side_state, upstream_side_cache),
        trace,
        false,
        true,
        owned_buffered_payload.as_ref(),
        None,
        Some(stable_permit),
        true,
    )?;
    if result.transferred_payload_ownership() {
        *owned_buffered_payload = None;
    }
    Ok(SyncSendAttempt::Complete(result))
}

pub(crate) fn perform_sync_session_transition(
    context: &mut PacketContext<'_, '_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    upstream_sequence: (&SharedIcmpSequenceState, &mut IcmpSequenceCache),
    owned_buffered_payload: &mut Option<BufferedPayload>,
    transition: SyncSessionTransition,
) -> io::Result<PayloadSendResult> {
    let flow_state = context.flow_state;
    let (upstream_side_state, upstream_side_cache) = upstream_sequence;
    let trace = owned_buffered_payload
        .as_ref()
        .and_then(BufferedPayload::trace);
    match transition {
        SyncSessionTransition::Exhausted { old_session_id } => {
            if let Some(next_session) = flow_state
                .handoff_upstream_session(
                    old_session_id,
                    context.t_event
                        + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs),
                )
                .map_err(|error| {
                    super::flow_mutation_io_error("ICMP cadence session-pool handoff failed", error)
                })?
            {
                activate_upstream_receive_session(
                    context.cfg,
                    flow_state,
                    None,
                    upstream_side_state,
                    upstream_side_cache,
                    next_session,
                )?;
                let expected_ack_destination_id =
                    cache.expected_upstream_ack_destination_id(handles)?;
                let now = Instant::now();
                flow_state.maintain_upstream_session_pool_until(
                    expected_ack_destination_id,
                    now,
                    now + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs),
                )?;
                return Ok(deferred_payload_send_result(context.t_event));
            }
            let expected_ack_destination_id =
                cache.expected_upstream_ack_destination_id(handles)?;
            let payload = match owned_buffered_payload.take() {
                Some(payload) => payload,
                None => {
                    let now = Instant::now();
                    flow_state.maintain_upstream_session_pool_until(
                        expected_ack_destination_id,
                        now,
                        now + std::time::Duration::from_secs(
                            context.cfg.icmp_handshake_timeout_secs,
                        ),
                    )?;
                    return Ok(deferred_payload_send_result(context.t_event));
                }
            };
            let new_session_id = crate::net::framing_shim::SessionId::fresh()?;
            let buffered_len = payload.payload_len();
            let session_started_at = payload.received_at();
            let outcome = flow_state
                .begin_upstream_rekey(
                    old_session_id,
                    new_session_id,
                    expected_ack_destination_id,
                    session_started_at
                        .saturating_duration_since(context.t_start)
                        .as_secs()
                        .max(1),
                    session_started_at
                        + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs),
                    payload,
                )
                .map_err(|error| {
                    super::flow_mutation_io_error("ICMP cadence rekey failed", error)
                })?;
            log_handshake_begin(
                context.cfg,
                context.worker_id,
                trace,
                &outcome,
                buffered_len,
            );
            retry_due_upstream_negotiation(
                context,
                handles,
                cache,
                upstream_side_state,
                upstream_side_cache,
                Some(new_session_id),
            )?;
            Ok(deferred_payload_send_result(context.t_event))
        }
        SyncSessionTransition::BeginHandshake { negotiation } => {
            let payload = owned_buffered_payload.as_ref().ok_or_else(|| {
                io::Error::other("sync handshake lost buffered payload ownership")
            })?;
            let started_at = payload.received_at();
            let started_s = started_at
                .saturating_duration_since(context.t_start)
                .as_secs()
                .max(1);
            let buffered_len = payload.payload_len();
            let absolute_deadline = started_at
                + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs);
            let prepared = crate::flow_state::PreparedReplyIdHandshake::new(
                negotiation.reply_id(),
                negotiation.session_key(),
                started_s,
                absolute_deadline,
                started_at,
            );
            let flow_transaction = flow_state.try_reserve_client_flow().map_err(|error| {
                super::reservation_io_error("reserve synchronized ICMP handshake", error)
            })?;
            let outcome = flow_state
                .begin_upstream_reply_id_handshake_with_owned_payload_under(
                    &flow_transaction,
                    prepared,
                    owned_buffered_payload,
                )
                .map_err(|error| {
                    super::flow_authority_io_error(
                        "synchronized ICMP handshake transition failed",
                        error,
                    )
                })?;
            drop(flow_transaction);
            log_handshake_begin(
                context.cfg,
                context.worker_id,
                trace,
                &outcome,
                buffered_len,
            );
            if outcome.should_send_control() {
                retry_due_upstream_negotiation(
                    context,
                    handles,
                    cache,
                    upstream_side_state,
                    upstream_side_cache,
                    Some(negotiation.session_key().session_id()),
                )?;
            }
            Ok(deferred_payload_send_result(context.t_event))
        }
    }
}

#[inline]
fn deferred_payload_send_result(at: Instant) -> PayloadSendResult {
    PayloadSendResult {
        outcome: HandledSendOutcome::Deferred,
        attempted_at: at,
        completed_at: at,
        retained_recovery_payload: false,
        deferred_control: None,
    }
}

mod ack;
pub(crate) use ack::{observe_reply_id_ack, reply_id_ack_is_reserve_local};

mod debug_kernel_echo;
pub(crate) use debug_kernel_echo::activate_upstream_receive_session;
use debug_kernel_echo::debug_kernel_echo_self_handshake_ack;

#[cfg(all(test, not(miri)))]
mod tests;
