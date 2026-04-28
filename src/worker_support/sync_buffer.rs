use super::cache::{CachedClientState, CachedSendRoute};
use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::flow_key::ClientFlowKey;
use crate::flow_state::FlowRuntimeState;
use crate::net::params::CanonicalAddr;
use crate::net::payload::{PayloadEvent, WirePayload, send_payload};
use crate::net::session::handle_send_result;
use crate::net::sock_mgr::SocketHandles;
use crate::net::sync_icmp::{
    C2uKeepaliveDecision, SharedSyncIcmpState, SyncIcmpCache, classify_c2u_keepalive,
    remember_request_seq, reset_session,
};
use crate::stats::StatsSink;
use std::time::Instant;

pub(crate) struct BufferedSyncPayload {
    src_is_icmp: bool,
    src_ident: u16,
    src_seq: u16,
    dst_proto: SupportedProtocol,
    payload: Vec<u8>,
}

impl BufferedSyncPayload {
    #[inline]
    pub(crate) fn from_wire(wire: &WirePayload<'_>) -> Self {
        Self {
            src_is_icmp: wire.src_is_icmp,
            src_ident: wire.src_ident,
            src_seq: wire.src_seq,
            dst_proto: wire.dst_proto,
            payload: wire.payload.to_vec(),
        }
    }

    #[inline]
    pub(crate) fn as_event(&self) -> PayloadEvent<'_> {
        PayloadEvent::UserData(WirePayload {
            src_is_icmp: self.src_is_icmp,
            src_ident: self.src_ident,
            src_seq: self.src_seq,
            dst_proto: self.dst_proto,
            payload: &self.payload,
            pub_len: self.payload.len(),
        })
    }
}

#[inline]
fn empty_icmp_reply_event(seq: u16) -> PayloadEvent<'static> {
    PayloadEvent::SyncKeepalive(WirePayload {
        src_is_icmp: true,
        src_ident: 0,
        src_seq: seq,
        dst_proto: SupportedProtocol::ICMP,
        payload: &[],
        pub_len: 0,
    })
}

#[inline]
fn send_local_keepalive_reply(
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    flow_state: &FlowRuntimeState,
    handles: &mut SocketHandles,
    route: &CachedSendRoute,
    wire: &WirePayload<'_>,
) {
    let reply_event = empty_icmp_reply_event(wire.src_seq);
    let send_res = send_payload(
        &handles.client_sock,
        handles.client_connected,
        handles.listen_sock_type,
        &route.dest_sa,
        &reply_event,
        route.icmp_header_id,
        false,
        Some(wire.src_seq),
    );
    handle_send_result(
        false,
        worker_id,
        t_start,
        t_recv,
        cfg,
        stats,
        flow_state,
        0,
        false,
        false,
        &send_res,
        handles.client_connected,
        &route.dest_sa,
        None,
    );
}

#[inline]
pub(crate) fn handle_c2u_keepalive(
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
    wire: &WirePayload<'_>,
) {
    match classify_c2u_keepalive(cfg, wire, sync_state, sync_cache) {
        Ok(C2uKeepaliveDecision::Consume) => {}
        Ok(C2uKeepaliveDecision::ReplyLocally) => {
            let reply_route = default_reply_route.cloned().or_else(|| {
                let dest = handles.client_peer.map(|peer| {
                    CanonicalAddr::new(
                        peer.addr,
                        handles
                            .locked_flow
                            .and_then(ClientFlowKey::icmp_ident)
                            .unwrap_or(peer.id),
                    )
                })?;
                Some(CachedClientState::build_local_keepalive_reply_route(
                    handles, dest,
                ))
            });
            if let Some(reply_route) = reply_route.as_ref() {
                send_local_keepalive_reply(
                    worker_id,
                    t_start,
                    t_recv,
                    cfg,
                    stats,
                    flow_state,
                    handles,
                    reply_route,
                    wire,
                );
            } else {
                log_debug_dir!(
                    cfg.debug_logs.drops,
                    worker_id,
                    true,
                    "dropping keepalive reply with no locked client address"
                );
            }
        }
        Err(e) => log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            true,
            "classify_c2u_keepalive error: {}",
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
) -> Option<BufferedSyncPayload> {
    match event {
        PayloadEvent::UserData(wire) => {
            if wire.src_is_icmp {
                remember_request_seq(sync_state, sync_cache, &wire);
            }
            Some(BufferedSyncPayload::from_wire(&wire))
        }
        PayloadEvent::SyncKeepalive(wire) => {
            handle_c2u_keepalive(
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
                &wire,
            );
            None
        }
    }
}

#[inline]
pub(crate) fn sync_session_on_lock_transition(
    cfg: &RuntimeConfig,
    was_locked: &mut bool,
    locked: bool,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
) {
    if *was_locked && !locked {
        reset_session(cfg, sync_state, sync_cache);
    }
    *was_locked = locked;
}

#[cfg(test)]
mod tests {
    use super::BufferedSyncPayload;
    use crate::cli::SupportedProtocol;
    use crate::net::params::CanonicalAddr;
    use crate::net::payload::{PayloadEvent, WirePayload};
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
        SocketHandles {
            locked_flow: None,
            client_peer: None,
            client_connected: false,
            client_sock: udp_socket_clone(),
            listen_sock_type: Type::DGRAM, // UDP sockets are always DGRAM
            upstream: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4444)),
                4444,
            ),
            upstream_local: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555)),
                5555,
            ),
            upstream_sock_type: Type::DGRAM,
            upstream_connected: true,
            upstream_sock: udp_socket_clone(),
            version: 0,
        }
    }

    #[test]
    fn buffered_sync_payload_round_trips_validated_user_data() {
        let event = PayloadEvent::UserData(WirePayload {
            src_is_icmp: true,
            src_ident: 1234,
            src_seq: 77,
            dst_proto: SupportedProtocol::ICMP,
            payload: b"payload",
            pub_len: 7,
        });

        let buffered = BufferedSyncPayload::from_wire(event.wire());
        let replay = buffered.as_event();
        let wire = replay.wire();
        assert!(replay.is_user_data());
        assert!(wire.src_is_icmp);
        assert_eq!(wire.src_ident, 1234);
        assert_eq!(wire.src_seq, 77);
        assert_eq!(wire.dst_proto, SupportedProtocol::ICMP);
        assert_eq!(wire.payload, b"payload");
        assert_eq!(wire.len(), 7);
    }

    #[test]
    fn local_keepalive_reply_route_uses_destination_peer_id_for_raw_listener() {
        let handles = test_handles();
        let dest = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999)),
            9999,
        );
        let route = CachedClientState::build_local_keepalive_reply_route(&handles, dest);
        assert_eq!(route.icmp_header_id, 9999);
        assert_eq!(
            route.dest_sa.as_socket().expect("cached keepalive dest"),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999))
        );
    }

    #[test]
    fn local_keepalive_reply_route_uses_realized_listen_id_for_dgram_listener() {
        let handles = test_handles();
        let dest = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999)),
            9999,
        );
        let route = CachedClientState::build_local_keepalive_reply_route(&handles, dest);
        assert_eq!(route.icmp_header_id, 9999);
        assert_eq!(
            route.dest_sa.as_socket().expect("cached keepalive dest"),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999))
        );
    }
}
