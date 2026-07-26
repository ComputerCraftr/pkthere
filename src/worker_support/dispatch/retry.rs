use super::{release_pre_sequence_send_authorities, send_payload_event_now_with_accounting_inner};
use crate::net::icmp_sequence::{IcmpSequenceCache, SharedIcmpSequenceState};
use crate::net::payload::{PayloadEvent, outbound_control_payload_event, send_payload_with_lease};
use crate::net::session::{HandledSendOutcome, handle_send_result};
use crate::net::sock_mgr::SocketHandles;
use crate::worker_support::{CachedClientState, PacketContext};
use std::io;
use std::time::Instant;

struct NegotiationPayloadSend<'state, 'payload> {
    flow_state: &'state crate::flow_state::FlowRuntimeState,
    lease: crate::flow_state::ReplyIdControlSendLease,
    control_sequence: u16,
    destination: &'payload socket2::SockAddr,
    policy: pkthere_socket_policy::SocketSendPolicy,
    source_ip: Option<std::net::IpAddr>,
    outbound: &'payload crate::net::payload::OutboundPayloadEvent<'payload>,
}

impl<Flow, Protocol>
    crate::worker_support::context::StableSendTransaction<
        Flow,
        crate::net::managed_socket::ManagedSendLease<'_>,
        Protocol,
    > for NegotiationPayloadSend<'_, '_>
{
    type SendResult = io::Result<crate::net::managed_socket::ManagedSendResult>;
    type Output = (
        Self::SendResult,
        Instant,
        Result<
            crate::flow_state::ReplyIdControlSendCompletion,
            crate::flow_state::ReplyIdHandshakeInvariantError,
        >,
        Option<crate::flow_state::DeferredPeerControl>,
    );

    fn send(
        &mut self,
        _flow: &mut Flow,
        send_lease: &crate::net::managed_socket::ManagedSendLease<'_>,
        _protocol: &mut Protocol,
    ) -> Self::SendResult {
        send_payload_with_lease(
            send_lease,
            self.destination,
            self.policy,
            self.source_ip,
            self.outbound,
        )
    }

    fn complete(
        self,
        _flow: &mut Flow,
        _socket: &crate::net::managed_socket::ManagedSendLease<'_>,
        _protocol: &mut Protocol,
        send_result: Self::SendResult,
    ) -> Self::Output {
        let completed_at = Instant::now();
        let sent = send_result.is_ok();
        let session_id = self.lease.session_id;
        let completion = self
            .flow_state
            .try_complete_upstream_reply_id_negotiation_send(
                self.lease,
                self.control_sequence,
                sent,
                completed_at,
            );
        let deferred = completion.as_ref().ok().and_then(|completion| {
            if matches!(
                completion,
                crate::flow_state::ReplyIdControlSendCompletion::Stale
                    | crate::flow_state::ReplyIdControlSendCompletion::ResetWon
            ) {
                None
            } else {
                self.flow_state.complete_deferred_upstream_control_response(
                    session_id,
                    self.control_sequence,
                    sent,
                )
            }
        });
        (send_result, completed_at, completion, deferred)
    }
}

#[inline]
pub(super) fn explicit_reply_id_ack(icmp: &crate::net::payload::IcmpPayloadMeta) -> bool {
    icmp.acknowledges_reply_id() && !icmp.negotiates_reply_id()
}

#[inline]
pub(super) fn reflected_kernel_echo_negotiation_matches(
    icmp: &crate::net::payload::IcmpPayloadMeta,
    upstream_local_id: u16,
) -> bool {
    icmp.reply_id_negotiation().is_some_and(|negotiation| {
        negotiation.is_negotiate() && negotiation.reply_id() == upstream_local_id
    }) && icmp.flow_identity().remote_source_id() == upstream_local_id
}

fn release_unsequenced_control_or_fatal(
    context: &mut PacketContext<'_, '_>,
    lease: crate::flow_state::ReplyIdControlSendLease,
    stable_permit: crate::worker_support::StableForwardPermit<'_>,
) {
    let released = context
        .flow_state
        .release_unsequenced_upstream_negotiation(lease, Instant::now());
    drop(stable_permit);
    if released.is_err() {
        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
            "unsequenced ICMP control lease could not be returned"
        ));
    }
}

pub(crate) fn retry_due_upstream_negotiation(
    context: &mut PacketContext<'_, '_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    sequence_state: &SharedIcmpSequenceState,
    sequence_cache: &mut IcmpSequenceCache,
    new_session: Option<crate::net::framing_shim::SessionId>,
) -> io::Result<bool> {
    if let Some(session_id) = new_session {
        crate::net::icmp_sequence::install_outbound_request_session(
            sequence_state,
            sequence_cache,
            session_id,
        )
        .map_err(io::Error::other)?;
    }
    let flow_read = match context.flow_state.try_topology_read(context.flow_lane) {
        Ok(read) => read,
        Err(error) if !error.class().is_fatal() => return Ok(false),
        Err(error) => {
            return Err(io::Error::other(format!(
                "stable negotiation flow unavailable: {error}"
            )));
        }
    };
    let mut snapshot_cache = crate::flow_state::FlowSnapshotCache::new();
    let flow_snapshot = match context.flow_state.admission_snapshot_with_read(
        &flow_read,
        &mut snapshot_cache,
        Instant::now(),
    ) {
        Ok(snapshot) => snapshot,
        Err(error) if !error.class().is_fatal() => return Ok(false),
        Err(error) => {
            return Err(io::Error::other(format!(
                "stable negotiation snapshot failed: {error}"
            )));
        }
    };
    let stable_permit =
        crate::worker_support::StableForwardPermit::for_upstream(flow_read, flow_snapshot, handles);
    context.flow_snapshot = Some(stable_permit.snapshot());
    let expected_ack_destination_id = cache.expected_upstream_ack_destination_id(handles)?;
    if context.flow_state.upstream_reply_id_acked() {
        let now = Instant::now();
        context.flow_state.maintain_upstream_session_pool_until(
            expected_ack_destination_id,
            now,
            now + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs),
        )?;
    }
    let pending_lease = context
        .flow_state
        .try_lease_due_upstream_reply_id_negotiation(Instant::now())
        .map_err(|_| {
            io::Error::other(
                "ICMP negotiation state was internally inconsistent while leasing control",
            )
        })?;
    let Some(lease) = pending_lease else {
        return Ok(false);
    };
    if let Err(missing) = crate::net::icmp_sequence::load_installed_outbound_session(
        sequence_state,
        sequence_cache,
        lease.session_id,
    ) {
        release_unsequenced_control_or_fatal(context, lease, stable_permit);
        crate::net::icmp_sequence::install_outbound_request_session(
            sequence_state,
            sequence_cache,
            missing.session_id,
        )
        .map_err(io::Error::other)?;
        return Ok(true);
    }
    let prepared_session = match crate::net::icmp_sequence::claim_prepared_outbound_session(
        sequence_state,
        sequence_cache,
        lease.session_id,
    ) {
        Ok(prepared_session) => prepared_session,
        Err(error) => {
            release_unsequenced_control_or_fatal(context, lease, stable_permit);
            return Err(io::Error::other(error));
        }
    };
    let cached_send = match cache.acquire_prepared_send(handles) {
        Ok(send_lease) => send_lease,
        Err(error) => {
            release_unsequenced_control_or_fatal(context, lease, stable_permit);
            return Err(error);
        }
    };
    let super::super::cache::CachedSendLease {
        socket: send_lease,
        destination,
        source_ip: send_source_ip,
        icmp_header_id: cached_icmp_header_id,
        icmp_source_id: cached_icmp_source_id,
    } = cached_send;
    if let Err(error) = stable_permit.validate(context.flow_state, handles) {
        release_pre_sequence_send_authorities(send_lease, Some(stable_permit));
        return Err(error);
    }
    let stable_send = match crate::worker_support::StableSendCore::new(stable_permit)
        .acquire_socket(send_lease)
        .reserve_protocol(prepared_session)
    {
        Ok(stable_send) => stable_send,
        Err(error) => return Err(io::Error::other(error)),
    };
    let control_seq = stable_send.protocol().sequence();
    let source_id = cached_icmp_source_id;
    let control = lease.control;
    let outbound = outbound_control_payload_event(
        control,
        cached_icmp_header_id,
        true,
        control_seq,
        source_id,
        lease.session_id,
    );
    let sequence_record_result = context
        .flow_state
        .record_upstream_negotiation_sequence(&lease, control_seq);
    let sequence_record = match sequence_record_result {
        Ok(record) => record,
        Err(_) => {
            drop(stable_send);
            return Err(io::Error::other(
                "ICMP negotiation sequence lease became stale",
            ));
        }
    };
    if matches!(
        sequence_record,
        crate::flow_state::ReplyIdControlSequenceRecord::ResetWon
            | crate::flow_state::ReplyIdControlSequenceRecord::HandshakeAdvanced
    ) {
        drop(stable_send);
        return Ok(false);
    }
    crate::net::icmp_sequence::publish_outbound_request_seq(sequence_state, stable_send.protocol());
    let attempted_at = Instant::now();
    let (send_res, completed_at, completion, deferred) =
        stable_send.perform(NegotiationPayloadSend {
            flow_state: context.flow_state,
            lease,
            control_sequence: control_seq,
            destination,
            policy: handles.upstream.policy.send_policy,
            source_ip: send_source_ip,
            outbound: &outbound,
        });
    context
        .flow_state
        .invalidate_maintenance_after_control_send();
    let control_event = PayloadEvent::session_control_v3(
        source_id,
        cached_icmp_header_id,
        control_seq,
        crate::cli::SupportedProtocol::ICMP,
        control,
    );
    handle_send_result(
        context,
        true,
        &control_event,
        crate::net::session::SendOutcome {
            result: &send_res,
            attempted_at,
            completed_at,
            account_success: true,
            destination,
            trace: None,
            trace_kind: crate::net::session::SendTraceKind::Forward,
        },
    );
    let completion = completion.map_err(|error| {
        context.stats.invariant_failure(true);
        crate::runtime_support::publish_process_fatal(format_args!(
            "ICMP negotiation sent-sequence accounting corrupted: {error:?}"
        ));
        io::Error::other("ICMP negotiation sent-sequence accounting corrupted")
    })?;
    if matches!(
        completion,
        crate::flow_state::ReplyIdControlSendCompletion::Stale
    ) {
        return Err(io::Error::other(
            "ICMP negotiation send lease became stale during socket I/O",
        ));
    }
    if completion == crate::flow_state::ReplyIdControlSendCompletion::ResetWon {
        return Ok(true);
    }
    if let Some(crate::flow_state::DeferredPeerControl::ResetRequired {
        control: reset,
        observed_at,
    }) = deferred
        && !context.flow_state.accept_upstream_rollover_challenge(
            reset,
            expected_ack_destination_id,
            observed_at,
            observed_at + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs),
        )?
    {
        return Err(io::Error::other(
            "deferred ICMP negotiation reset no longer matched sent control evidence",
        ));
    }
    Ok(true)
}

pub(crate) fn retry_due_upstream_recovery_payload(
    context: &mut PacketContext<'_, '_>,
    handles: &SocketHandles,
    cache: &mut CachedClientState,
    upstream_sequence_state: &SharedIcmpSequenceState,
    upstream_sequence_cache: &mut IcmpSequenceCache,
) -> io::Result<bool> {
    let Some(lease) = context
        .flow_state
        .lease_due_upstream_recovery_payload(Instant::now())
        .map_err(|_| io::Error::other("ICMP recovery payload ownership was inconsistent"))?
    else {
        return Ok(false);
    };
    let event = lease.payload.as_event();
    let trace = lease.payload.trace();
    let payload_len = lease.payload.payload_len();
    let received_at = lease.payload.received_at();
    let send_result = super::super::context::prepared_upstream_permit(
        context.flow_state,
        context.flow_lane,
        handles,
        upstream_sequence_state,
        upstream_sequence_cache,
    )
    .and_then(|permit| {
        send_payload_event_now_with_accounting_inner(
            context,
            &event,
            handles,
            cache,
            (upstream_sequence_state, upstream_sequence_cache),
            trace,
            false,
            false,
            None,
            Some(&lease.token),
            Some(permit),
            false,
        )
    });
    let sent = send_result
        .as_ref()
        .is_ok_and(|result| matches!(result.outcome, HandledSendOutcome::Sent { .. }));
    let completed_at = send_result
        .as_ref()
        .map_or_else(|_| Instant::now(), |result| result.completed_at);
    let completion = context
        .flow_state
        .complete_upstream_recovery_payload_send(lease, sent, completed_at)
        .map_err(|_| io::Error::other("ICMP recovery payload ownership became stale"))?;
    if sent && !completion.timeout_requested && context.cfg.stats_interval_mins != 0 {
        let attempted_at = send_result
            .as_ref()
            .map_or(completed_at, |result| result.attempted_at);
        context.stats.send_add(
            true,
            payload_len as u64,
            received_at,
            attempted_at,
            completed_at,
        );
    }
    if completion.timeout_requested {
        return Ok(true);
    }
    if let Ok(result) = &send_result
        && let Some(deferred) = result.deferred_control
    {
        super::apply_deferred_upstream_control(
            context,
            handles,
            cache,
            upstream_sequence_state,
            deferred,
        )?;
    }
    if let Some(reset) = completion.pending_reset {
        let expected_ack_destination_id = cache.expected_upstream_ack_destination_id(handles)?;
        let flow_transaction = context
            .flow_state
            .try_reserve_client_flow()
            .map_err(|error| {
                super::super::reservation_io_error("reserve ICMP reset retry", error)
            })?;
        let recovery = context
            .flow_state
            .recover_upstream_session_under(
                &flow_transaction,
                crate::flow_state::UpstreamRecoveryRequest {
                    sequences: upstream_sequence_state,
                    reset,
                    expected_ack_destination_id,
                    observed_at: completed_at,
                    absolute_deadline: completed_at
                        + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs),
                    started_s: completed_at
                        .saturating_duration_since(context.t_start)
                        .as_secs()
                        .max(1),
                },
            )
            .map_err(|error| {
                super::super::flow_mutation_io_error("ICMP reset retry failed", error)
            })?;
        if let crate::flow_state::UpstreamSessionRecovery::Recovered {
            retired_sessions, ..
        } = recovery
        {
            upstream_sequence_state.retire_outbound_sessions(&retired_sessions);
        }
    }
    send_result.map(|_| true)
}
