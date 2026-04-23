use super::{CachedClientState, PacketContext, SequenceContext};
use crate::cli::RuntimeConfig;
use crate::flow_state::{FlowRuntimeState, ReplyIdHandshakeAck};
use crate::net::icmp_sequence::{IcmpSequenceCache, SharedIcmpSequenceState, reset_sequence_state};
use crate::net::payload::{
    BufferedPayload, PayloadEvent, allocate_send_sequence, outbound_payload_event,
    reply_id_negotiation_for_c2u, send_payload,
};
use crate::net::session::handle_send_result;
use crate::net::sock_mgr::SocketHandles;
use crate::packet_trace::PacketTraceId;
use std::io;

use super::handshake_trace::{
    HandshakeAckMatched, log_handshake_ack_ignored, log_handshake_ack_matched, log_handshake_begin,
};
use crate::flow_state::ReplyIdHandshakeAckIgnored;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserPayloadRoute {
    ForwardNow,
    BufferFirstHandshakePayload,
    BufferSyncPayload,
    DropHandshakePending,
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
pub(crate) fn record_user_payload_route(context: PacketContext<'_>, route: UserPayloadRoute) {
    if route.records_activity() {
        context
            .flow_state
            .record_activity(context.t_start, context.t_event);
    }
}

#[derive(Debug)]
pub(crate) enum ObserveAckResult {
    Matched {
        payload: BufferedPayload,
        peer_source_id: u16,
        peer_reply_id: u16,
        trigger_trace: PacketTraceId,
    },
    Duplicate {
        trigger_trace: PacketTraceId,
    },
    WrongAckDestinationId {
        trigger_trace: PacketTraceId,
    },
    NoPending {
        trigger_trace: PacketTraceId,
    },
    NotAck,
}

#[inline]
pub(crate) fn refresh_lock_and_sync_state(
    cfg: &RuntimeConfig,
    flow_state: &FlowRuntimeState,
    was_locked: &mut bool,
    sequence_state: &SharedIcmpSequenceState,
    sequence_cache: &mut IcmpSequenceCache,
) -> bool {
    let locked_now = flow_state.is_locked();
    if *was_locked && !locked_now {
        reset_sequence_state(cfg.debug_logs.packets, sequence_state, sequence_cache);
    }
    *was_locked = locked_now;
    locked_now
}

#[inline]
pub(crate) fn send_user_payload_event(
    context: PacketContext<'_>,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    cache: &CachedClientState,
    sequences: SequenceContext<'_>,
    trace: Option<PacketTraceId>,
) -> io::Result<()> {
    const C2U: bool = true;
    let PacketContext {
        t_start,
        t_event: t_recv,
        flow_state,
        ..
    } = context;

    if let PayloadEvent::UserPayload {
        icmp: Some(icmp), ..
    } = event
    {
        crate::net::icmp_sequence::remember_request_seq(
            sequences.client_state,
            sequences.client_cache,
            icmp,
        );
    }
    let source_id = cache.route.icmp_source_id();
    let local_reply_id = handles.upstream.upstream_local_filter.id;
    let reply_id_negotiation =
        reply_id_negotiation_for_c2u(event, flow_state.upstream_reply_id_acked(), local_reply_id);
    if let Some(reply_id_negotiation) = reply_id_negotiation
        && reply_id_negotiation.negotiate
    {
        let started_s = t_recv.saturating_duration_since(t_start).as_secs().max(1);
        let new_payload_len = event.payload_len();
        let outcome = flow_state.begin_upstream_reply_id_handshake(
            reply_id_negotiation.reply_id,
            started_s,
            BufferedPayload::from_event(event, trace),
        );
        log_handshake_begin(
            context.cfg,
            context.worker_id,
            trace,
            &outcome,
            new_payload_len,
        );
        let handshake_route = match &outcome {
            crate::flow_state::ReplyIdHandshakeBegin::Started { .. } => {
                UserPayloadRoute::BufferFirstHandshakePayload
            }
            crate::flow_state::ReplyIdHandshakeBegin::PendingReused { .. } => {
                UserPayloadRoute::DropHandshakePending
            }
            crate::flow_state::ReplyIdHandshakeBegin::Ignored => UserPayloadRoute::ForwardNow,
        };
        record_user_payload_route(context, handshake_route);
        if matches!(
            outcome,
            crate::flow_state::ReplyIdHandshakeBegin::PendingReused { .. }
        ) && let Some(trace) = trace
        {
            super::packet_dump::log_packet_disposition(
                context.cfg,
                trace,
                super::packet_dump::PacketDisposition::DropHandshakePending,
            );
        }
        if outcome.should_send_control() {
            let control_event = PayloadEvent::session_control_negotiation(
                source_id,
                cache.route.icmp_header_id,
                0,
                crate::cli::SupportedProtocol::ICMP,
                reply_id_negotiation,
            );
            let outbound = outbound_payload_event(
                &control_event,
                cache.route.icmp_header_id,
                C2U,
                allocate_send_sequence(
                    C2U,
                    &control_event,
                    true,
                    sequences.upstream_state,
                    sequences.upstream_cache,
                ),
                source_id,
                Some(reply_id_negotiation),
            )?;
            let send_res = send_payload(
                &handles.upstream_sock,
                handles.upstream.upstream_connected,
                &cache.route.dest_sa,
                handles.upstream.policy.send_policy,
                cache.route.source_ip,
                &outbound,
            );
            handle_send_result(
                context,
                C2U,
                &control_event,
                crate::net::session::SendOutcome {
                    result: &send_res,
                    socket_connected: handles.upstream.upstream_connected,
                    destination: &cache.route.dest_sa,
                    disconnect: None,
                    trace: None,
                    trace_kind: crate::net::session::SendTraceKind::Forward,
                },
            );
        }
        return Ok(());
    }
    record_user_payload_route(context, UserPayloadRoute::ForwardNow);
    send_payload_event_now(context, event, handles, cache, sequences, trace)
}

/// Sends an already-routed event without recording activity or re-entering
/// reply-ID handshake buffering.
#[inline]
pub(crate) fn send_payload_event_now(
    context: PacketContext<'_>,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    cache: &CachedClientState,
    sequences: SequenceContext<'_>,
    trace: Option<PacketTraceId>,
) -> io::Result<()> {
    const C2U: bool = true;
    let source_id = cache.route.icmp_source_id();
    let reply_id_negotiation = reply_id_negotiation_for_c2u(
        event,
        context.flow_state.upstream_reply_id_acked(),
        handles.upstream.upstream_local_filter.id,
    );
    let outbound = match outbound_payload_event(
        event,
        cache.route.icmp_header_id,
        C2U,
        allocate_send_sequence(
            C2U,
            event,
            true,
            sequences.upstream_state,
            sequences.upstream_cache,
        ),
        source_id,
        reply_id_negotiation,
    ) {
        Ok(outbound) => outbound,
        Err(err) => {
            if let Some(trace) = trace {
                super::packet_dump::log_packet_disposition(
                    context.cfg,
                    trace,
                    super::packet_dump::PacketDisposition::SendFailed,
                );
            }
            return Err(err);
        }
    };
    let send_res = send_payload(
        &handles.upstream_sock,
        handles.upstream.upstream_connected,
        &cache.route.dest_sa,
        handles.upstream.policy.send_policy,
        cache.route.source_ip,
        &outbound,
    );
    handle_send_result(
        context,
        C2U,
        event,
        crate::net::session::SendOutcome {
            result: &send_res,
            socket_connected: handles.upstream.upstream_connected,
            destination: &cache.route.dest_sa,
            disconnect: None,
            trace,
            trace_kind: crate::net::session::SendTraceKind::Forward,
        },
    );
    Ok(())
}

#[inline]
pub(crate) fn send_sync_payload_or_cadence(
    context: PacketContext<'_>,
    handles: &SocketHandles,
    cache: &CachedClientState,
    upstream_sequence: (&SharedIcmpSequenceState, &mut IcmpSequenceCache),
    buffered_payload: Option<&BufferedPayload>,
) -> io::Result<()> {
    const C2U: bool = true;
    let PacketContext {
        worker_id,
        t_start,
        t_event: t_send,
        cfg,
        stats: _,
        flow_state,
    } = context;
    let (upstream_side_state, upstream_side_cache) = upstream_sequence;
    let trace = buffered_payload.and_then(BufferedPayload::trace);

    let synthetic_event;
    let event = if let Some(payload) = buffered_payload {
        payload.as_event()
    } else {
        let Some(ident) = handles
            .listener
            .listener_flow
            .outbound_destination()
            .map(|peer_addr| peer_addr.id)
        else {
            log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                C2U,
                "synthetic cadence packet error: missing listener outbound destination"
            );
            unreachable!("synthetic cadence packet validation must not fail")
        };
        synthetic_event = PayloadEvent::cadence_packet(ident, 0);
        synthetic_event
    };

    let source_id = cache.route.icmp_source_id();
    let local_reply_id = handles.upstream.upstream_local_filter.id;
    let reply_id_negotiation =
        reply_id_negotiation_for_c2u(&event, flow_state.upstream_reply_id_acked(), local_reply_id);
    if let Some(reply_id_negotiation) = reply_id_negotiation
        && reply_id_negotiation.negotiate
    {
        let started_s = t_send.saturating_duration_since(t_start).as_secs().max(1);
        let new_payload_len = event.payload_len();
        let outcome = flow_state.begin_upstream_reply_id_handshake(
            reply_id_negotiation.reply_id,
            started_s,
            BufferedPayload::from_event(&event, trace),
        );
        log_handshake_begin(
            context.cfg,
            context.worker_id,
            trace,
            &outcome,
            new_payload_len,
        );
        if matches!(
            outcome,
            crate::flow_state::ReplyIdHandshakeBegin::PendingReused { .. }
        ) && let Some(trace) = trace
        {
            super::packet_dump::log_packet_disposition(
                context.cfg,
                trace,
                super::packet_dump::PacketDisposition::DropHandshakePending,
            );
        }
        if outcome.should_send_control() {
            let control_event = PayloadEvent::session_control_negotiation(
                source_id,
                cache.route.icmp_header_id,
                0,
                crate::cli::SupportedProtocol::ICMP,
                reply_id_negotiation,
            );
            let outbound = outbound_payload_event(
                &control_event,
                cache.route.icmp_header_id,
                C2U,
                allocate_send_sequence(
                    C2U,
                    &control_event,
                    true,
                    upstream_side_state,
                    upstream_side_cache,
                ),
                source_id,
                Some(reply_id_negotiation),
            )?;
            let send_res = send_payload(
                &handles.upstream_sock,
                handles.upstream.upstream_connected,
                &cache.route.dest_sa,
                handles.upstream.policy.send_policy,
                cache.route.source_ip,
                &outbound,
            );
            handle_send_result(
                context,
                C2U,
                &control_event,
                crate::net::session::SendOutcome {
                    result: &send_res,
                    socket_connected: handles.upstream.upstream_connected,
                    destination: &cache.route.dest_sa,
                    disconnect: None,
                    trace: None,
                    trace_kind: crate::net::session::SendTraceKind::Forward,
                },
            );
        }
        return Ok(());
    }
    let outbound = match outbound_payload_event(
        &event,
        cache.route.icmp_header_id,
        C2U,
        allocate_send_sequence(C2U, &event, true, upstream_side_state, upstream_side_cache),
        source_id,
        reply_id_negotiation,
    ) {
        Ok(outbound) => outbound,
        Err(err) => {
            if let Some(trace) = trace {
                super::packet_dump::log_packet_disposition(
                    context.cfg,
                    trace,
                    super::packet_dump::PacketDisposition::SendFailed,
                );
            }
            return Err(err);
        }
    };
    let send_res = send_payload(
        &handles.upstream_sock,
        handles.upstream.upstream_connected,
        &cache.route.dest_sa,
        handles.upstream.policy.send_policy,
        cache.route.source_ip,
        &outbound,
    );
    handle_send_result(
        context,
        C2U,
        &event,
        crate::net::session::SendOutcome {
            result: &send_res,
            socket_connected: handles.upstream.upstream_connected,
            destination: &cache.route.dest_sa,
            disconnect: None,
            trace,
            trace_kind: crate::net::session::SendTraceKind::Forward,
        },
    );
    Ok(())
}

#[inline]
pub(crate) fn observe_reply_id_ack(
    cfg: &RuntimeConfig,
    worker_id: usize,
    c2u: bool,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    flow_state: &FlowRuntimeState,
    ack_trace: PacketTraceId,
) -> ObserveAckResult {
    if c2u {
        return ObserveAckResult::NotAck;
    }
    let icmp = match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        }
        | PayloadEvent::SessionControl { icmp, .. } => icmp,
        _ => return ObserveAckResult::NotAck,
    };
    if explicit_reply_id_ack(icmp) {
        if icmp.inbound_header_ident() == handles.upstream.upstream_local_filter.id {
            let peer_reply_id = match icmp.reply_id_negotiation() {
                Some(negotiation) => negotiation.reply_id,
                None => icmp.flow_identity().remote_source_id,
            };
            let peer_source_id = icmp.flow_identity().remote_source_id;
            // The Echo destination acknowledges our advertised receive ID. The
            // reply ID carried by the ACK is the peer's independent return
            // endpoint and must not be used to match our pending handshake.
            let acknowledged = flow_state
                .ack_upstream_reply_id_handshake(icmp.inbound_header_ident(), Some(ack_trace));
            let pending_payload = matches!(acknowledged, ReplyIdHandshakeAck::Matched { .. });
            log_debug!(
                cfg.debug_logs.handles,
                "[reply_id_ack] c2u=false matched upstream ACK: header_id={} peer_source_id={} peer_reply_id={} pending_payload={}",
                icmp.inbound_header_ident(),
                peer_source_id,
                peer_reply_id,
                pending_payload
            );
            let res = match acknowledged {
                ReplyIdHandshakeAck::Matched {
                    expected_ack_destination_id,
                    payload,
                    trigger_trace: _,
                } => {
                    log_handshake_ack_matched(
                        cfg,
                        worker_id,
                        HandshakeAckMatched {
                            expected_ack_destination_id,
                            observed_ack_destination_id: icmp.inbound_header_ident(),
                            peer_source_id,
                            peer_reply_id,
                            buffered_len: payload.payload_len(),
                            buffered_trace: payload.trace(),
                            trigger_trace: Some(ack_trace),
                        },
                    );
                    ObserveAckResult::Matched {
                        payload,
                        peer_source_id,
                        peer_reply_id,
                        trigger_trace: ack_trace,
                    }
                }
                ReplyIdHandshakeAck::Ignored(reason) => {
                    log_handshake_ack_ignored(cfg, worker_id, reason, icmp.inbound_header_ident());
                    match reason {
                        ReplyIdHandshakeAckIgnored::NoPending { .. } => {
                            ObserveAckResult::NoPending {
                                trigger_trace: ack_trace,
                            }
                        }
                        ReplyIdHandshakeAckIgnored::AlreadyAcked { .. } => {
                            ObserveAckResult::Duplicate {
                                trigger_trace: ack_trace,
                            }
                        }
                        ReplyIdHandshakeAckIgnored::WrongDestinationId { .. } => {
                            ObserveAckResult::WrongAckDestinationId {
                                trigger_trace: ack_trace,
                            }
                        }
                    }
                }
            };
            return res;
        } else {
            log_debug!(
                cfg.debug_logs.drops,
                "[reply_id_ack] c2u=false filtered ACK before handshake: observed_ack_destination_id={} expected_ack_destination_id={} peer_source_id={} peer_reply_id={:?}",
                icmp.inbound_header_ident(),
                handles.upstream.upstream_local_filter.id,
                icmp.flow_identity().remote_source_id,
                icmp.reply_id_negotiation()
                    .map(|negotiation| negotiation.reply_id)
            );
        }
    }

    if debug_kernel_echo_self_handshake_ack(cfg, c2u, event, handles)
        && let Some(revealed_id) = icmp.reply_id_negotiation().map(|n| n.reply_id)
    {
        let observed_ack_destination_id = icmp.inbound_header_ident();
        let res = match flow_state
            .ack_upstream_reply_id_handshake(observed_ack_destination_id, Some(ack_trace))
        {
            ReplyIdHandshakeAck::Matched {
                expected_ack_destination_id,
                payload,
                trigger_trace: _,
            } => {
                log_handshake_ack_matched(
                    cfg,
                    worker_id,
                    HandshakeAckMatched {
                        expected_ack_destination_id,
                        observed_ack_destination_id,
                        peer_source_id: revealed_id,
                        peer_reply_id: revealed_id,
                        buffered_len: payload.payload_len(),
                        buffered_trace: payload.trace(),
                        trigger_trace: Some(ack_trace),
                    },
                );
                ObserveAckResult::Matched {
                    payload,
                    peer_source_id: revealed_id,
                    peer_reply_id: revealed_id,
                    trigger_trace: ack_trace,
                }
            }
            ReplyIdHandshakeAck::Ignored(reason) => {
                log_handshake_ack_ignored(cfg, worker_id, reason, observed_ack_destination_id);
                match reason {
                    ReplyIdHandshakeAckIgnored::NoPending { .. } => ObserveAckResult::NoPending {
                        trigger_trace: ack_trace,
                    },
                    ReplyIdHandshakeAckIgnored::AlreadyAcked { .. } => {
                        ObserveAckResult::Duplicate {
                            trigger_trace: ack_trace,
                        }
                    }
                    ReplyIdHandshakeAckIgnored::WrongDestinationId { .. } => {
                        ObserveAckResult::WrongAckDestinationId {
                            trigger_trace: ack_trace,
                        }
                    }
                }
            }
        };
        return res;
    }

    ObserveAckResult::NotAck
}

#[inline]
fn debug_kernel_echo_self_handshake_ack(
    cfg: &RuntimeConfig,
    c2u: bool,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
) -> bool {
    if !cfg.debug_behavior.icmp_kernel_echo_self_handshake
        || c2u
        || cfg.upstream_proto != crate::cli::SupportedProtocol::ICMP
        || handles
            .upstream
            .policy
            .icmp
            .is_some_and(|policy| policy.can_honor_disjoint_ids())
    {
        return false;
    }
    let PayloadEvent::SessionControl { icmp, .. } = event else {
        return false;
    };
    reflected_kernel_echo_negotiation_matches(icmp, handles.upstream.upstream_local_filter.id)
}

#[inline]
fn explicit_reply_id_ack(icmp: &crate::net::payload::IcmpPayloadMeta) -> bool {
    icmp.acknowledges_reply_id() && !icmp.negotiates_reply_id()
}

#[inline]
fn reflected_kernel_echo_negotiation_matches(
    icmp: &crate::net::payload::IcmpPayloadMeta,
    upstream_local_id: u16,
) -> bool {
    icmp.reply_id_negotiation().is_some_and(|negotiation| {
        negotiation.negotiate && !negotiation.ack && negotiation.reply_id == upstream_local_id
    }) && icmp.flow_identity().remote_source_id == upstream_local_id
}

#[cfg(test)]
mod tests {
    use super::{explicit_reply_id_ack, reflected_kernel_echo_negotiation_matches};
    use crate::net::framing_shim::ReplyIdNegotiation;
    use crate::net::payload::IcmpPayloadMeta;

    fn icmp_meta(advertised_reply_id: Option<u16>, negotiate: bool, ack: bool) -> IcmpPayloadMeta {
        IcmpPayloadMeta::new(
            2002,
            2002,
            7,
            advertised_reply_id.map(|reply_id| ReplyIdNegotiation {
                reply_id,
                negotiate,
                ack,
            }),
        )
    }

    #[test]
    fn explicit_reply_id_ack_ignores_reflected_negotiation() {
        let reflected = icmp_meta(Some(2002), true, false);
        assert!(!explicit_reply_id_ack(&reflected));
    }

    #[test]
    fn explicit_reply_id_ack_accepts_ack_only() {
        let ack = icmp_meta(Some(2002), false, true);
        assert!(explicit_reply_id_ack(&ack));
    }

    #[test]
    fn explicit_reply_id_ack_ignores_mixed_negotiate_ack() {
        let mixed = icmp_meta(Some(2002), true, true);
        assert!(!explicit_reply_id_ack(&mixed));
    }

    #[test]
    fn debug_kernel_echo_self_reflection_requires_matching_no_disjoint_id() {
        let reflected = icmp_meta(Some(2002), true, false);
        assert!(reflected_kernel_echo_negotiation_matches(&reflected, 2002));

        let wrong_id = icmp_meta(Some(3003), true, false);
        assert!(!reflected_kernel_echo_negotiation_matches(&wrong_id, 2002));

        let explicit = icmp_meta(Some(2002), true, false);
        assert!(reflected_kernel_echo_negotiation_matches(&explicit, 2002));

        let mixed = icmp_meta(Some(2002), true, true);
        assert!(!reflected_kernel_echo_negotiation_matches(&mixed, 2002));
    }

    use super::ObserveAckResult;
    use super::{UserPayloadRoute, observe_reply_id_ack, record_user_payload_route};
    use crate::cli::SupportedProtocol;
    use crate::flow_key::SocketLegFlow;
    use crate::flow_state::FlowRuntimeState;
    use crate::net::params::CanonicalAddr;
    use crate::net::payload::BufferedPayload;
    use crate::net::payload::PayloadEvent;
    use crate::net::sock_mgr::{ListenerMetadata, SocketHandles, UpstreamMetadata};
    use crate::worker_support::PacketTraceId;
    use crate::worker_support::admission_test_support::test_config;
    use pkthere_socket_policy::{
        IcmpPolicyIntent, SocketRole, TimeoutAction, resolve_socket_policy_with_icmp_intent,
    };
    use socket2::Socket;
    use socket2::{Domain, Type};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    fn test_handles() -> SocketHandles {
        let upstream_remote =
            CanonicalAddr::new(SocketAddr::from_str("127.0.0.1:4444").unwrap(), 4444);
        let upstream_local =
            CanonicalAddr::new(SocketAddr::from_str("127.0.0.1:5555").unwrap(), 5555);
        let listen_policy = resolve_socket_policy_with_icmp_intent(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
            IcmpPolicyIntent::default(),
        );
        let upstream_policy = resolve_socket_policy_with_icmp_intent(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
            IcmpPolicyIntent::default(),
        );
        let listen_local_filter =
            CanonicalAddr::new(SocketAddr::from_str("127.0.0.1:3333").unwrap(), 3333);
        SocketHandles::new(
            ListenerMetadata {
                flow: None,
                listener_flow: SocketLegFlow::empty(),
                listen_local_filter,
                listen_local_kernel_addr: SocketAddr::from_str("127.0.0.1:3333").unwrap(),
                evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                    SocketRole::Listener,
                    0,
                    SocketAddr::from_str("127.0.0.1:3333").unwrap(),
                ),
                listener_connected: false,
                sock_type: Type::DGRAM,
                policy: listen_policy,
                parser: crate::net::packet_headers::select_packet_parser(
                    SupportedProtocol::UDP,
                    Domain::IPV4,
                    listen_policy,
                )
                .expect("listener parser"),
            },
            Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap(),
            UpstreamMetadata {
                upstream_remote_filter: upstream_remote,
                upstream_local_filter: upstream_local,
                upstream_local_kernel_addr: upstream_local.addr,
                evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                    SocketRole::Upstream,
                    0,
                    upstream_local.addr,
                ),
                upstream_flow: SocketLegFlow::empty(),
                sock_type: Type::DGRAM,
                policy: upstream_policy,
                parser: crate::net::packet_headers::select_packet_parser(
                    SupportedProtocol::ICMP,
                    Domain::IPV4,
                    upstream_policy,
                )
                .expect("upstream parser"),
                upstream_connected: false,
            },
            Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap(),
            0,
        )
    }

    #[test]
    fn direct_handshake_destination_mismatch_preserves_pending_payload() {
        let cfg = test_config(crate::cli::IcmpReplyIdRequest::Default);
        let handles = test_handles();
        let flow_state = FlowRuntimeState::new();
        let dummy_trace = PacketTraceId {
            worker_id: 1,
            c2u: true,
            packet_id: 99,
        };

        let event = PayloadEvent::UserPayload {
            dst_proto: SupportedProtocol::UDP,
            bytes: b"hello",
            icmp: None,
        };

        flow_state.begin_upstream_reply_id_handshake(
            1234,
            100,
            BufferedPayload::from_event(&event, Some(dummy_trace)),
        );

        let ack_event = PayloadEvent::SessionControl {
            dst_proto: SupportedProtocol::ICMP,
            bytes: &[],
            icmp: crate::net::payload::IcmpPayloadMeta::new(
                5555,
                handles.upstream.upstream_local_filter.id,
                1,
                Some(crate::net::framing_shim::ReplyIdNegotiation {
                    reply_id: 5555,
                    negotiate: false,
                    ack: true,
                }),
            ),
        };

        let result = observe_reply_id_ack(
            &cfg,
            1,
            false,
            &ack_event,
            &handles,
            &flow_state,
            PacketTraceId {
                worker_id: 1,
                c2u: false,
                packet_id: 100,
            },
        );

        assert!(
            matches!(result, ObserveAckResult::WrongAckDestinationId { trigger_trace } if trigger_trace.packet_id == 100)
        );
        assert!(matches!(
            flow_state.ack_upstream_reply_id_handshake(1234, None),
            crate::flow_state::ReplyIdHandshakeAck::Matched { .. }
        ));
    }

    #[test]
    fn reply_ack_matches_echo_destination_not_peer_reply_id() {
        let cfg = test_config(crate::cli::IcmpReplyIdRequest::Default);
        let handles = test_handles();
        let flow_state = FlowRuntimeState::new();
        let buffered_trace = PacketTraceId {
            worker_id: 1,
            c2u: true,
            packet_id: 99,
        };
        let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"hello");
        flow_state.begin_upstream_reply_id_handshake(
            handles.upstream.upstream_local_filter.id,
            100,
            BufferedPayload::from_event(&event, Some(buffered_trace)),
        );

        let ack_event = PayloadEvent::SessionControl {
            dst_proto: SupportedProtocol::ICMP,
            bytes: &[],
            icmp: crate::net::payload::IcmpPayloadMeta::new(
                7777,
                handles.upstream.upstream_local_filter.id,
                1,
                Some(crate::net::framing_shim::ReplyIdNegotiation {
                    reply_id: 9999,
                    negotiate: false,
                    ack: true,
                }),
            ),
        };
        let ack_trace = PacketTraceId {
            worker_id: 1,
            c2u: false,
            packet_id: 100,
        };

        let result =
            observe_reply_id_ack(&cfg, 1, false, &ack_event, &handles, &flow_state, ack_trace);

        assert!(matches!(
            result,
            ObserveAckResult::Matched {
                peer_source_id: 7777,
                peer_reply_id: 9999,
                trigger_trace,
                ..
            } if trigger_trace == ack_trace
        ));
    }

    #[test]
    fn activity_is_recorded_once_only_for_admitted_user_routes() {
        let cfg = test_config(crate::cli::IcmpReplyIdRequest::Default);
        let stats = crate::stats::Stats::with_worker_shards(1);
        let stats = stats.shard(0);
        let flow_state = FlowRuntimeState::new();
        let start = Instant::now();

        record_user_payload_route(
            super::PacketContext::new(
                0,
                start,
                start + Duration::from_secs(4),
                &cfg,
                stats.as_ref(),
                &flow_state,
            ),
            UserPayloadRoute::ForwardNow,
        );
        assert_eq!(flow_state.last_seen_s(), 4);

        let route = UserPayloadRoute::DropHandshakePending;
        record_user_payload_route(
            super::PacketContext::new(
                0,
                start,
                start + Duration::from_secs(9),
                &cfg,
                stats.as_ref(),
                &flow_state,
            ),
            route,
        );
        assert_eq!(
            flow_state.last_seen_s(),
            4,
            "{route:?} must not refresh activity"
        );

        record_user_payload_route(
            super::PacketContext::new(
                0,
                start,
                start + Duration::from_secs(7),
                &cfg,
                stats.as_ref(),
                &flow_state,
            ),
            UserPayloadRoute::BufferFirstHandshakePayload,
        );
        assert_eq!(flow_state.last_seen_s(), 7);

        record_user_payload_route(
            super::PacketContext::new(
                0,
                start,
                start + Duration::from_secs(8),
                &cfg,
                stats.as_ref(),
                &flow_state,
            ),
            UserPayloadRoute::BufferSyncPayload,
        );
        assert_eq!(flow_state.last_seen_s(), 8);
    }
}
