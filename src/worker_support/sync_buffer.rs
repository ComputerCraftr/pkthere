use super::PacketContext;
use super::cache::{CachedClientState, CachedSendRoute};
use crate::cli::SupportedProtocol;
use crate::net::framing_shim::ReplyIdNegotiation;
use crate::net::icmp_sequence::{IcmpSequenceCache, SharedIcmpSequenceState};
use crate::net::payload::{
    BufferedPayload, C2uSessionControlDecision, PayloadEvent, classify_c2u_session_control_event,
    outbound_payload_event, send_payload,
};
use crate::net::session::handle_send_result;
use crate::net::sock_mgr::SocketHandles;
use crate::packet_trace::PacketTraceId;
use crate::worker_support::packet_dump::{PacketDisposition, log_packet_disposition};

pub(crate) enum BufferedSyncUpdate {
    Buffered {
        buffered_trace: PacketTraceId,
        replaced_trace: Option<PacketTraceId>,
    },
    Keep,
}

#[inline]
fn store_sync_payload(
    slot: &mut Option<BufferedPayload>,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
) -> BufferedSyncUpdate {
    let replaced_trace = slot
        .replace(BufferedPayload::from_event(event, Some(trace)))
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
    ack: ReplyIdNegotiation,
) -> PayloadEvent<'static> {
    PayloadEvent::session_control_negotiation(
        source_id,
        header_id,
        seq,
        SupportedProtocol::ICMP,
        ack,
    )
}

#[inline]
fn session_control_reply_id_for_route(
    event: &PayloadEvent<'_>,
    route: &CachedSendRoute,
) -> Option<ReplyIdNegotiation> {
    let icmp = match event {
        PayloadEvent::SessionControl { icmp, .. } => icmp,
        _ => return None,
    };
    let reply_id = route.icmp_advertised_reply_id();
    Some(ReplyIdNegotiation {
        reply_id,
        negotiate: false,
        ack: icmp.negotiates_reply_id(),
    })
}

#[inline]
pub(crate) fn handle_c2u_session_control(
    context: PacketContext<'_>,
    handles: &mut SocketHandles,
    client_sequence: (&SharedIcmpSequenceState, &mut IcmpSequenceCache),
    default_reply_route: Option<&CachedSendRoute>,
    event: &PayloadEvent<'_>,
    trace: Option<PacketTraceId>,
) {
    let PacketContext { worker_id, cfg, .. } = context;
    let (client_side_state, client_side_cache) = client_sequence;
    match classify_c2u_session_control_event(cfg, event, client_side_state, client_side_cache) {
        Ok(C2uSessionControlDecision::Forward) | Ok(C2uSessionControlDecision::Consume) => {
            if let Some(trace) = trace {
                log_packet_disposition(cfg, trace, PacketDisposition::ConsumeSessionControl);
            }
        }
        Ok(C2uSessionControlDecision::ReplyLocally) => {
            let reply_route = default_reply_route.cloned().or_else(|| {
                let dest = handles.listener.listener_flow.outbound_destination()?;
                Some(CachedClientState::build_local_session_control_reply_route(
                    handles, dest,
                ))
            });
            if let Some(reply_route) = reply_route.as_ref() {
                emit_local_session_control_reply(context, handles, reply_route, event, trace);
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
            }
        }
        Err(e) => {
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
        }
    }
}

#[inline]
fn emit_local_session_control_reply(
    context: PacketContext<'_>,
    handles: &mut SocketHandles,
    route: &CachedSendRoute,
    event: &PayloadEvent<'_>,
    trace: Option<PacketTraceId>,
) {
    let PacketContext { worker_id, cfg, .. } = context;
    let seq = match event {
        PayloadEvent::SessionControl { icmp, .. } => icmp.seq(),
        _ => unreachable!("local session-control reply requires session-control event"),
    };
    let source_id = route.icmp_source_id();
    let Some(ack) = session_control_reply_id_for_route(event, route) else {
        return;
    };
    let reply_event = empty_icmp_reply_event(seq, source_id, route.icmp_header_id, ack);
    let outbound = match outbound_payload_event(
        &reply_event,
        route.icmp_header_id,
        false,
        Some(seq),
        source_id,
        Some(ack),
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
            return;
        }
    };
    let send_res = send_payload(
        &handles.client_sock,
        handles.listener_connected(),
        &route.dest_sa,
        handles.listener.policy.send_policy,
        route.source_ip,
        &outbound,
    );
    handle_send_result(
        context,
        false,
        &reply_event,
        crate::net::session::SendOutcome {
            result: &send_res,
            socket_connected: handles.listener_connected(),
            destination: &route.dest_sa,
            disconnect: None,
            trace,
            trace_kind: crate::net::session::SendTraceKind::ReplySessionControl,
        },
    );
}

#[inline]
pub(crate) fn buffer_sync_event(
    context: PacketContext<'_>,
    handles: &mut SocketHandles,
    client_sequence: (&SharedIcmpSequenceState, &mut IcmpSequenceCache),
    default_reply_route: Option<&CachedSendRoute>,
    slot: &mut Option<BufferedPayload>,
    event: PayloadEvent<'_>,
    trace: PacketTraceId,
) -> BufferedSyncUpdate {
    let (client_side_state, client_side_cache) = client_sequence;
    match event {
        PayloadEvent::UserPayload { .. } => {
            super::record_user_payload_route(context, super::UserPayloadRoute::BufferSyncPayload);
            if let PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } = event
            {
                crate::net::icmp_sequence::remember_request_seq(
                    client_side_state,
                    client_side_cache,
                    &icmp,
                );
            }
            store_sync_payload(slot, &event, trace)
        }
        PayloadEvent::SessionControl { .. } => {
            handle_c2u_session_control(
                context,
                handles,
                (client_side_state, client_side_cache),
                default_reply_route,
                &event,
                Some(trace),
            );
            BufferedSyncUpdate::Keep
        }
        PayloadEvent::CadencePacket { .. } => {
            log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeCadence);
            BufferedSyncUpdate::Keep
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BufferedPayload, BufferedSyncUpdate, empty_icmp_reply_event,
        session_control_reply_id_for_route, store_sync_payload,
    };
    use crate::cli::{SupportedProtocol, TimeoutAction};
    use crate::endpoint::LogicalEndpoint;
    use crate::flow_key::{FlowTuple, SocketLegFlow};
    use crate::net::framing_shim::ReplyIdNegotiation;
    use crate::net::payload::PayloadEvent;
    use crate::net::sock_mgr::{ListenerMetadata, SocketHandles, UpstreamMetadata};
    use crate::worker_support::cache::CachedClientState;
    use crate::worker_support::test_support::udp_socket;
    use pkthere_socket_policy::{
        IcmpPolicyIntent, SocketRole, resolve_socket_policy_with_icmp_intent,
    };
    use socket2::{Domain, Type};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    fn test_handles() -> SocketHandles {
        let upstream_remote = LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4444)),
            4444,
        );
        let upstream_local = LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555)),
            5555,
        );
        let upstream_flow = SocketLegFlow::new(
            Some(FlowTuple::new(upstream_remote, upstream_local)),
            Some(FlowTuple::new(upstream_local, upstream_remote)),
        );
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
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
            IcmpPolicyIntent::default(),
        );
        SocketHandles::new(
            ListenerMetadata {
                flow: None,
                listener_flow: SocketLegFlow::empty(),
                listen_local_filter: LogicalEndpoint::from_socket_addr_with_id(
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3333)),
                    3333,
                ),
                listen_local_kernel_addr: SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    3333,
                )),
                evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                    SocketRole::Listener,
                    0,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3333)),
                ),
                sock_type: Type::DGRAM,
                policy: listen_policy,
                parser: crate::net::packet_headers::select_packet_parser(
                    SupportedProtocol::UDP,
                    Domain::IPV4,
                    listen_policy,
                )
                .expect("listener parser"),
            },
            udp_socket(),
            UpstreamMetadata {
                upstream_remote_filter: upstream_remote,
                upstream_local_filter: upstream_local,
                upstream_local_kernel_addr: upstream_local.to_socket_addr(),
                evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                    SocketRole::Upstream,
                    0,
                    upstream_local.to_socket_addr(),
                ),
                upstream_flow,
                sock_type: Type::DGRAM,
                policy: upstream_policy,
                parser: crate::net::packet_headers::select_packet_parser(
                    SupportedProtocol::UDP,
                    Domain::IPV4,
                    upstream_policy,
                )
                .expect("upstream parser"),
            },
            udp_socket(),
            0,
        )
    }

    #[test]
    fn buffered_sync_payload_round_trips_validated_user_data() {
        let event = PayloadEvent::user_payload(1234, 1234, 77, SupportedProtocol::ICMP, b"payload");

        let buffered = BufferedPayload::from_event(&event, None);
        let replay = buffered.as_event();
        assert!(replay.is_user_payload());
        match replay {
            PayloadEvent::UserPayload {
                dst_proto,
                bytes,
                icmp: Some(icmp),
            } => {
                assert_eq!(icmp.flow_identity().remote_source_id, 1234);
                assert_eq!(icmp.seq(), 77);
                assert_eq!(dst_proto, SupportedProtocol::ICMP);
                assert_eq!(bytes, b"payload");
            }
            other => panic!("unexpected replay event: {other:?}"),
        }
    }

    #[test]
    fn local_session_control_reply_route_uses_destination_peer_id_for_raw_listener() {
        let mut handles = test_handles();
        Arc::make_mut(&mut handles.listener).sock_type = Type::RAW;
        let dest = LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999)),
            9999,
        );
        let route = CachedClientState::build_local_session_control_reply_route(&handles, dest);
        assert_eq!(route.icmp_header_id, 9999);
        assert_eq!(
            route
                .dest_sa
                .as_socket()
                .expect("cached session-control dest"),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999))
        );
    }

    #[test]
    fn local_session_control_reply_route_uses_realized_listen_id_for_dgram_listener() {
        let handles = test_handles();
        let dest = LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999)),
            9999,
        );
        let route = CachedClientState::build_local_session_control_reply_route(&handles, dest);
        assert_eq!(route.icmp_header_id, 9999);
        assert_eq!(
            route
                .dest_sa
                .as_socket()
                .expect("cached session-control dest"),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999))
        );
    }

    #[test]
    fn session_control_ack_advertises_reply_id_not_source_id() {
        let route = CachedClientState::build_pending_session_control_reply_route(
            LogicalEndpoint::from_socket_addr_with_id(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40001)),
                40001,
            ),
            7777,
            Ipv4Addr::LOCALHOST.into(),
            9999,
        );
        let request = PayloadEvent::session_control_negotiation(
            40000,
            9999,
            12,
            SupportedProtocol::ICMP,
            ReplyIdNegotiation {
                reply_id: 40001,
                negotiate: true,
                ack: false,
            },
        );

        let ack = session_control_reply_id_for_route(&request, &route)
            .expect("session-control route should produce ack metadata");
        assert_eq!(ack.reply_id, 9999);
        assert_ne!(ack.reply_id, route.icmp_source_id());
        assert!(ack.ack);
        assert!(!ack.negotiate);

        match empty_icmp_reply_event(12, route.icmp_source_id(), route.icmp_header_id, ack) {
            PayloadEvent::SessionControl { icmp, .. } => {
                assert_eq!(icmp.flow_identity().remote_source_id, 7777);
                assert_eq!(icmp.inbound_header_ident(), 40001);
                assert_eq!(icmp.advertised_reply_id(), Some(9999));
                assert!(icmp.acknowledges_reply_id());
            }
            other => panic!("unexpected ack event: {other:?}"),
        }
    }

    #[test]
    fn cadence_packet_keeps_existing_buffered_payload() {
        let update = BufferedSyncUpdate::Keep;
        assert!(matches!(update, BufferedSyncUpdate::Keep));
    }

    #[test]
    fn sync_replacement_reports_old_trace_and_keeps_new_trace_pending() {
        let first_trace = crate::packet_trace::PacketTraceId {
            worker_id: 0,
            c2u: true,
            packet_id: 10,
        };
        let second_trace = crate::packet_trace::PacketTraceId {
            packet_id: 11,
            ..first_trace
        };
        let first = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"first");
        let second = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"second");
        let mut slot = None;

        assert!(matches!(
            store_sync_payload(&mut slot, &first, first_trace),
            BufferedSyncUpdate::Buffered {
                buffered_trace,
                replaced_trace: None,
            } if buffered_trace == first_trace
        ));
        assert!(matches!(
            store_sync_payload(&mut slot, &second, second_trace),
            BufferedSyncUpdate::Buffered {
                buffered_trace,
                replaced_trace: Some(replaced_trace),
            } if buffered_trace == second_trace && replaced_trace == first_trace
        ));
        let buffered = slot.expect("replacement payload remains buffered");
        assert_eq!(buffered.trace(), Some(second_trace));
        assert!(matches!(
            buffered.as_event(),
            PayloadEvent::UserPayload { bytes, .. } if bytes == b"second"
        ));
    }
}
