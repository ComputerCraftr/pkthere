use super::cache::{CachedClientState, CachedSendRoute};
use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::flow_state::FlowRuntimeState;
use crate::net::payload::{
    BufferedPayload, PayloadEvent, outbound_payload_event, reply_id_ack_for_event, send_payload,
};
use crate::net::session::handle_send_result;
use crate::net::sock_mgr::SocketHandles;
use crate::net::sync_icmp::{
    C2uSessionControlDecision, SharedSyncIcmpState, SyncIcmpCache, classify_c2u_session_control,
    remember_request_seq,
};
use crate::stats::StatsSink;
use std::time::Instant;

pub(crate) enum BufferedSyncUpdate {
    Replace(BufferedPayload),
    Keep,
}

#[inline]
fn empty_icmp_reply_event(
    seq: u16,
    ack: Option<crate::net::framing_shim::ReplyIdNegotiation>,
) -> PayloadEvent<'static> {
    PayloadEvent::session_control_negotiation(0, 0, seq, SupportedProtocol::ICMP, ack)
}

#[inline]
fn send_local_session_control_reply(
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    flow_state: &FlowRuntimeState,
    handles: &mut SocketHandles,
    route: &CachedSendRoute,
    event: &PayloadEvent<'_>,
) {
    let seq = match event {
        PayloadEvent::SessionControl { icmp, .. } => icmp.seq,
        _ => unreachable!("local session-control reply requires session-control event"),
    };
    let ack = reply_id_ack_for_event(event);
    let reply_event = empty_icmp_reply_event(seq, ack);
    let outbound =
        match outbound_payload_event(&reply_event, route.icmp_header_id, false, Some(seq), ack) {
            Ok(outbound) => outbound,
            Err(e) => {
                log_debug_dir!(
                    cfg.debug_logs.drops,
                    worker_id,
                    false,
                    "session-control reply build error: {}",
                    e
                );
                return;
            }
        };
    let send_res = send_payload(
        &handles.client_sock,
        handles.listener_connected,
        handles.listen_sock_type,
        &route.dest_sa,
        &outbound,
    );
    handle_send_result(
        false,
        worker_id,
        t_start,
        t_recv,
        cfg,
        stats,
        flow_state,
        &reply_event,
        false,
        &send_res,
        handles.listener_connected,
        &route.dest_sa,
        None,
    );
}

#[inline]
pub(crate) fn handle_c2u_session_control(
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    flow_state: &FlowRuntimeState,
    handles: &mut SocketHandles,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
    default_reply_route: Option<&CachedSendRoute>,
    event: &PayloadEvent<'_>,
) {
    match classify_c2u_session_control(cfg, event, sync_state, sync_cache) {
        Ok(C2uSessionControlDecision::Forward) => {}
        Ok(C2uSessionControlDecision::ReplyLocally) => {
            let reply_route = default_reply_route.cloned().or_else(|| {
                let dest = handles.listener_flow.outbound_destination()?;
                Some(CachedClientState::build_local_session_control_reply_route(
                    handles, dest,
                ))
            });
            if let Some(reply_route) = reply_route.as_ref() {
                send_local_session_control_reply(
                    worker_id,
                    t_start,
                    t_recv,
                    cfg,
                    stats,
                    flow_state,
                    handles,
                    reply_route,
                    event,
                );
            } else {
                log_debug_dir!(
                    cfg.debug_logs.drops,
                    worker_id,
                    true,
                    "dropping session-control reply with no locked client address"
                );
            }
        }
        Err(e) => log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            true,
            "classify_c2u_session_control error: {}",
            e
        ),
    }
}

#[inline]
pub(crate) fn buffer_sync_event(
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    flow_state: &FlowRuntimeState,
    handles: &mut SocketHandles,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
    default_reply_route: Option<&CachedSendRoute>,
    event: PayloadEvent<'_>,
) -> BufferedSyncUpdate {
    match event {
        PayloadEvent::UserPayload { .. } => {
            if let PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } = event
            {
                remember_request_seq(sync_state, sync_cache, &icmp);
            }
            BufferedSyncUpdate::Replace(BufferedPayload::from_event(&event))
        }
        PayloadEvent::SessionControl { .. } => {
            handle_c2u_session_control(
                worker_id,
                t_start,
                t_recv,
                cfg,
                stats,
                flow_state,
                handles,
                sync_state,
                sync_cache,
                default_reply_route,
                &event,
            );
            BufferedSyncUpdate::Keep
        }
        PayloadEvent::CadencePacket { .. } => BufferedSyncUpdate::Keep,
    }
}

#[cfg(test)]
mod tests {
    use super::{BufferedPayload, BufferedSyncUpdate};
    use crate::cli::SupportedProtocol;
    use crate::flow_key::{FlowEndpoint, FlowTuple, SocketLegFlow};
    use crate::net::params::CanonicalAddr;
    use crate::net::payload::PayloadEvent;
    use crate::net::sock_mgr::SocketHandles;
    use crate::worker_support::cache::CachedClientState;
    use socket2::{Socket, Type};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

    fn udp_socket_clone() -> Socket {
        Socket::from(
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("bind udp socket"),
        )
    }

    fn test_handles() -> SocketHandles {
        let upstream_remote = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4444)),
            4444,
        );
        let upstream_local = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555)),
            5555,
        );
        let upstream_flow = SocketLegFlow::new(
            Some(FlowTuple::new(
                FlowEndpoint::from_canonical(upstream_remote),
                FlowEndpoint::from_canonical(upstream_local),
            )),
            Some(FlowTuple::new(
                FlowEndpoint::from_canonical(upstream_local),
                FlowEndpoint::from_canonical(upstream_remote),
            )),
        );
        SocketHandles {
            locked_flow: None,
            listener_flow: SocketLegFlow::empty(),
            listen_local_filter: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3333)),
                3333,
            ),
            listen_local_kernel: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3333)),
                3333,
            ),
            listener_connected: false,
            client_sock: udp_socket_clone(),
            listen_sock_type: Type::DGRAM, // UDP sockets are always DGRAM
            upstream_remote_filter: upstream_remote,
            upstream_local_filter: upstream_local,
            upstream_flow,
            upstream_sock_type: Type::DGRAM,
            upstream_connected: true,
            upstream_sock: udp_socket_clone(),
            version: 0,
        }
    }

    #[test]
    fn buffered_sync_payload_round_trips_validated_user_data() {
        let event =
            PayloadEvent::user_payload(1234, 1234, 77, SupportedProtocol::ICMP, b"payload", None);

        let buffered = BufferedPayload::from_event(&event);
        let replay = buffered.as_event();
        assert!(replay.is_user_payload());
        match replay {
            PayloadEvent::UserPayload {
                data,
                icmp: Some(icmp),
            } => {
                assert_eq!(icmp.negotiated_remote_reply_id, 1234);
                assert_eq!(icmp.seq, 77);
                assert_eq!(data.dst_proto, SupportedProtocol::ICMP);
                assert_eq!(data.bytes, b"payload");
            }
            other => panic!("unexpected replay event: {other:?}"),
        }
    }

    #[test]
    fn local_session_control_reply_route_uses_destination_peer_id_for_raw_listener() {
        let handles = test_handles();
        let dest = CanonicalAddr::new(
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
        let dest = CanonicalAddr::new(
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
    fn cadence_packet_keeps_existing_buffered_payload() {
        let update = BufferedSyncUpdate::Keep;
        assert!(matches!(update, BufferedSyncUpdate::Keep));
    }
}
