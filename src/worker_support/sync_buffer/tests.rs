use super::{
    BufferedPayload, BufferedSyncUpdate, empty_icmp_reply_event, session_control_reply_for_route,
    store_sync_payload,
};
use crate::cli::{SupportedProtocol, TimeoutAction};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{FlowTuple, SocketLegFlow};
use crate::net::framing_shim::{IcmpTunnelControl, ReplyIdNegotiation};
use crate::net::payload::PayloadEvent;
use crate::net::sock_mgr::{ListenerMetadata, SocketHandles, StateVersion, UpstreamMetadata};
use crate::worker_support::cache::CachedClientState;
use crate::worker_support::test_support::udp_socket;
use pkthere_socket_policy::{
    ProtocolPolicyIntent, SocketRole, resolve_socket_policy_with_protocol_intent,
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
    let listen_policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Listener,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let upstream_policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    SocketHandles::new(
        ListenerMetadata {
            flow: None,
            listener_flow: SocketLegFlow::empty(),
            listen_local_filter: LogicalEndpoint::from_socket_addr_with_id(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3333)),
                3333,
            ),
            listen_local_kernel_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3333)),
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
        StateVersion::INITIAL,
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
            assert_eq!(icmp.flow_identity().remote_source_id(), 1234);
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
        crate::net::framing_shim::SessionId::for_tests(),
        SupportedProtocol::ICMP,
        ReplyIdNegotiation::negotiate(40001).expect("nonzero test reply ID"),
    );

    let ack = session_control_reply_for_route(&request, &route)
        .expect("session-control route should produce ack metadata");
    let IcmpTunnelControl::NegotiateAck(ack_metadata) = ack else {
        panic!("expected negotiate ACK");
    };
    assert_eq!(ack_metadata.reply_id(), 9999);
    assert_ne!(ack_metadata.reply_id(), route.icmp_source_id());
    assert!(ack_metadata.is_ack());
    assert!(!ack_metadata.is_negotiate());

    match empty_icmp_reply_event(12, route.icmp_source_id(), route.icmp_header_id, ack) {
        PayloadEvent::SessionControl { icmp, .. } => {
            assert_eq!(icmp.flow_identity().remote_source_id(), 7777);
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
    let first_trace = crate::diagnostics::PacketTraceId {
        worker_id: 0,
        c2u: true,
        packet_id: 10,
    };
    let second_trace = crate::diagnostics::PacketTraceId {
        packet_id: 11,
        ..first_trace
    };
    let first = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"first");
    let second = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"second");
    let state = crate::flow_state::FlowRuntimeState::new();

    let (first_update, first_copies) = crate::allocation_test_support::count_payload_copies(|| {
        store_sync_payload(&state, &first, first_trace, std::time::Instant::now())
    });
    assert_eq!(first_copies, 1);
    assert!(matches!(
        first_update,
        BufferedSyncUpdate::Buffered {
            buffered_trace,
            replaced_trace: None,
        } if buffered_trace == first_trace
    ));
    let (second_update, replacement_copies) =
        crate::allocation_test_support::count_payload_copies(|| {
            store_sync_payload(&state, &second, second_trace, std::time::Instant::now())
        });
    assert_eq!(replacement_copies, 1);
    assert!(matches!(
        second_update,
        BufferedSyncUpdate::Buffered {
            buffered_trace,
            replaced_trace: Some(replaced_trace),
        } if buffered_trace == second_trace && replaced_trace == first_trace
    ));
    let (buffered, lease_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state
            .lease_sync_send()
            .expect("lease replacement")
            .expect("replacement is pending")
            .payload
            .expect("replacement payload remains buffered")
    });
    assert_eq!(lease_copies, 0);
    assert_eq!(buffered.trace(), Some(second_trace));
    assert_eq!(buffered.payload_storage_strong_count(), 1);
    assert!(matches!(
        buffered.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes == b"second"
    ));
}

#[test]
fn buffered_payload_retains_original_receive_timestamp() {
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"timestamp");
    let received_at = std::time::Instant::now();
    let payload = crate::net::payload::BufferedPayload::from_event_at(&event, None, received_at);
    assert_eq!(payload.received_at(), received_at);
}
