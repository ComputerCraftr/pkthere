use super::{explicit_reply_id_ack, reflected_kernel_echo_negotiation_matches};
use crate::net::framing_shim::ReplyIdNegotiation;
use crate::net::payload::IcmpPayloadMeta;

fn icmp_meta(negotiation: Option<ReplyIdNegotiation>) -> IcmpPayloadMeta {
    IcmpPayloadMeta::new(
        2002,
        2002,
        7,
        crate::net::framing_shim::SessionId::for_tests(),
        negotiation,
    )
}
#[test]
fn explicit_reply_id_ack_ignores_reflected_negotiation() {
    let reflected = icmp_meta(ReplyIdNegotiation::negotiate(2002));
    assert!(!explicit_reply_id_ack(&reflected));
}
#[test]
fn explicit_reply_id_ack_accepts_ack_only() {
    let ack = icmp_meta(ReplyIdNegotiation::acknowledge(2002));
    assert!(explicit_reply_id_ack(&ack));
}

#[test]
fn reply_id_control_type_cannot_represent_mixed_flags_or_zero_ids() {
    assert_eq!(ReplyIdNegotiation::negotiate(0), None);
    assert_eq!(ReplyIdNegotiation::acknowledge(0), None);
}
#[test]
fn debug_kernel_echo_self_reflection_requires_matching_no_disjoint_id() {
    let reflected = icmp_meta(ReplyIdNegotiation::negotiate(2002));
    assert!(reflected_kernel_echo_negotiation_matches(&reflected, 2002));

    let wrong_id = icmp_meta(ReplyIdNegotiation::negotiate(3003));
    assert!(!reflected_kernel_echo_negotiation_matches(&wrong_id, 2002));

    let explicit = icmp_meta(ReplyIdNegotiation::negotiate(2002));
    assert!(reflected_kernel_echo_negotiation_matches(&explicit, 2002));
}

use super::ObserveAckResult;
use super::{
    UserPayloadRoute, observe_reply_id_ack, outbound_upstream_session_id,
    record_user_payload_route, send_user_payload_event,
};
use crate::allocation_test_support_tests::ExactDatagramDeliveryProgress;
use crate::cli::SupportedProtocol;
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::flow_state::FlowRuntimeState;
use crate::net::payload::BufferedPayload;

#[test]
fn stable_forwarding_authority_does_not_embed_the_session_pool_snapshot() {
    let projection = std::mem::size_of::<crate::worker_support::context::StableFlowProjection>();
    let admission = std::mem::size_of::<crate::flow_state::FlowAdmissionSnapshot>();
    assert!(
        projection <= 40,
        "stable projection grew to {projection} bytes"
    );
    assert!(
        projection < admission,
        "stable projection must not embed the {admission}-byte admission snapshot"
    );
}
use crate::net::payload::PayloadEvent;
use crate::net::sock_mgr::{ListenerMetadata, SocketHandles, StateVersion, UpstreamMetadata};
use crate::worker_support::PacketTraceId;
use crate::worker_support::admission_test_support::test_config;
use crate::worker_support::test_support::udp_socket;
use pkthere_socket_policy::{
    IcmpPolicyIntent, ProtocolPolicyIntent, SocketRole, TimeoutAction,
    resolve_socket_policy_with_protocol_intent,
};
use socket2::{Domain, Type};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::{Duration, Instant};

#[test]
fn outbound_session_transition_errors_are_retryable_but_other_invariants_are_not() {
    let rekey = std::io::Error::other(crate::net::icmp_sequence::RekeyRequired {
        session_id: crate::net::framing_shim::SessionId::for_tests(),
    });
    assert!(super::is_retryable_outbound_session_race(&rekey));
    assert!(!super::is_retryable_outbound_session_race(
        &std::io::Error::other("unrelated invariant")
    ));
}

fn record_negotiation_sequence(flow_state: &FlowRuntimeState, sequence: u16) {
    let lease = flow_state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("pending negotiation lease");
    flow_state
        .record_upstream_negotiation_sequence(&lease, sequence)
        .expect("record negotiation sequence");
    flow_state.complete_upstream_reply_id_negotiation_send(lease, sequence, true, Instant::now());
}

fn test_handles() -> SocketHandles {
    let upstream_remote = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::from_str("127.0.0.1:4444").unwrap(),
        4444,
    );
    let upstream_local = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::from_str("127.0.0.1:5555").unwrap(),
        5555,
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
        ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let listen_local_filter = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::from_str("127.0.0.1:3333").unwrap(),
        3333,
    );
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
            upstream_flow: SocketLegFlow::empty(),
            sock_type: Type::DGRAM,
            policy: upstream_policy,
            parser: crate::net::packet_headers::select_packet_parser(
                SupportedProtocol::ICMP,
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
fn locked_udp_production_send_path_is_allocation_and_copy_free_with_exact_delivery() {
    const COUNTED_PACKETS: usize = 10_000;
    const TOTAL_PACKETS: usize = COUNTED_PACKETS + 1;
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP forwarding sink");
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bound UDP forwarding timeout");
    let remote_address = receiver.local_addr().expect("UDP forwarding sink address");
    let (mut delivery, received_count) = ExactDatagramDeliveryProgress::new();
    let receiving = std::thread::spawn(move || {
        let mut payload = [0_u8; 16];
        let mut received = 0;
        while received < TOTAL_PACKETS {
            let (length, _) = receiver
                .recv_from(&mut payload)
                .expect("receive every forwarded UDP payload");
            assert_eq!(&payload[..length], b"stable");
            received += 1;
            ExactDatagramDeliveryProgress::record_receive(&received_count, received);
        }
        received
    });

    let mut cfg = test_config(crate::cli::IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    cfg.upstream_proto = SupportedProtocol::UDP;
    let manager = crate::worker_support::test_support::unused_manager(remote_address);
    let handles = manager
        .capture_startup_handles()
        .expect("capture production UDP manager handles");
    let remote_client =
        LogicalEndpoint::from_socket_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 41000)));
    let client_source = socket2::SockAddr::from(remote_client.to_socket_addr());
    let receive_spec = crate::worker_support::admission_test_support::synthetic_receive_context(
        crate::worker_support::SocketLeg::ClientFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        pkthere_socket_policy::ReceiveEvidencePolicy {
            peer_source: pkthere_socket_policy::PeerSourceRequirement::SourceMetadata,
            protocol_id: pkthere_socket_policy::ProtocolIdRequirement::None,
        },
        Some(remote_client),
        Some(cfg.listen.id()),
        Some(cfg.listen.ip()),
    );
    let mut receive_spec = receive_spec;
    receive_spec.admission.locked_flow = Some(ClientFlowKey::Udp(remote_client));
    let flow_state = FlowRuntimeState::new();
    flow_state
        .reserve_client_flow()
        .publish_locked(ClientFlowKey::Udp(remote_client))
        .expect("publish stable UDP flow");
    let stats = crate::stats::Stats::new(1, false).expect("disabled allocation test stats");
    let mut recorder = stats.try_recorder(0).expect("disabled stats recorder");
    let client_sequences = crate::net::icmp_sequence::SharedIcmpSequenceState::new();
    let upstream_sequences = crate::net::icmp_sequence::SharedIcmpSequenceState::new();
    let mut client_cache = client_sequences.cache();
    let mut upstream_cache = upstream_sequences.cache();
    let mut flow_snapshot_cache = crate::flow_state::FlowSnapshotCache::new();
    let mut cache = crate::worker_support::CachedClientState::new(true, 0, &cfg, &handles, false)
        .expect("initialize UDP send cache");
    let started = Instant::now();

    let mut forward_once = || {
        let admitted = match crate::worker_support::packet_admission::admit_wire_packet(
            true,
            &cfg,
            receive_spec,
            b"stable",
            Some(&client_source),
        ) {
            Ok(admitted) => admitted,
            other => panic!("locked UDP packet was not admitted: {other:?}"),
        };
        assert!(admitted.lock_candidate().is_none());
        let flow_read = flow_state
            .try_topology_read(crate::flow_state::FlowReaderLane::new(0))
            .expect("acquire stable UDP flow lane");
        let snapshot = flow_state
            .admission_snapshot_with_read(&flow_read, &mut flow_snapshot_cache, Instant::now())
            .expect("read the production-published flow snapshot");
        let permit =
            crate::worker_support::StableForwardPermit::for_upstream(flow_read, snapshot, &handles);
        let outcome = send_user_payload_event(
            &mut super::PacketContext::new(
                0,
                started,
                Instant::now(),
                &cfg,
                &mut recorder,
                &flow_state,
            ),
            &admitted.event,
            &handles,
            &mut cache,
            crate::worker_support::SequenceContext::new(
                &client_sequences,
                &mut client_cache,
                &upstream_sequences,
                &mut upstream_cache,
            ),
            None,
            permit,
        )
        .expect("forward stable UDP payload");
        assert!(matches!(
            outcome,
            super::UserPayloadSendDecision::Sent {
                outcome: crate::net::session::HandledSendOutcome::Sent { .. },
                ..
            }
        ));
        delivery.record_send();
    };

    forward_once();
    let forbidden_authorities =
        crate::allocation_test_support::StableForwardAuthoritySnapshot::capture();
    let ((((), copies), candidates), allocations) =
        crate::allocation_test_support::count_allocations(|| {
            crate::allocation_test_support::count_lock_candidate_constructions(|| {
                crate::allocation_test_support::count_payload_copies(|| {
                    for _ in 0..COUNTED_PACKETS {
                        forward_once();
                    }
                })
            })
        });

    assert_eq!((allocations, copies, candidates), (0, 0, 0));
    forbidden_authorities.assert_unchanged();
    assert_eq!(
        receiving.join().expect("join UDP forwarding sink"),
        TOTAL_PACKETS
    );
}

#[test]
fn active_icmp_c2u_production_send_path_is_allocation_copy_and_global_authority_free() {
    const COUNTED_PACKETS: usize = 10_000;
    const TOTAL_PACKETS: usize = COUNTED_PACKETS + 1;
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ICMP frame sink");
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set ICMP frame sink timeout");
    let remote_address = receiver.local_addr().expect("ICMP frame sink address");
    let (mut delivery, received_count) = ExactDatagramDeliveryProgress::new();
    let receiving = std::thread::spawn(move || {
        let mut packet = [0_u8; 128];
        let mut received = 0;
        while received < TOTAL_PACKETS {
            let (length, _) = receiver
                .recv_from(&mut packet)
                .expect("receive every forwarded ICMP frame");
            assert!(length > b"stable".len());
            assert!(packet[..length].ends_with(b"stable"));
            received += 1;
            ExactDatagramDeliveryProgress::record_receive(&received_count, received);
        }
        received
    });
    let mut cfg = test_config(crate::cli::IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    cfg.upstream_proto = SupportedProtocol::ICMP;
    let manager = crate::worker_support::test_support::unused_manager(remote_address);
    let handles = manager
        .capture_startup_handles()
        .expect("capture production ICMP test manager handles");
    let client = LogicalEndpoint::from_socket_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 41_000)));
    let flow_key = ClientFlowKey::Udp(client);
    let client_source = socket2::SockAddr::from(client.to_socket_addr());
    let mut receive_spec = crate::worker_support::admission_test_support::synthetic_receive_context(
        crate::worker_support::SocketLeg::ClientFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        pkthere_socket_policy::ReceiveEvidencePolicy {
            peer_source: pkthere_socket_policy::PeerSourceRequirement::SourceMetadata,
            protocol_id: pkthere_socket_policy::ProtocolIdRequirement::None,
        },
        Some(client),
        Some(cfg.listen.id()),
        Some(cfg.listen.ip()),
    );
    receive_spec.admission.locked_flow = Some(flow_key);
    let flow_state = FlowRuntimeState::new();
    flow_state
        .reserve_client_flow()
        .publish_locked(flow_key)
        .expect("publish active ICMP forwarding flow");
    crate::worker_support::test_support::activate_upstream_session_for_forwarding(&flow_state, 17);
    let stats = crate::stats::Stats::new(1, false).expect("disabled ICMP test stats");
    let mut recorder = stats.try_recorder(0).expect("disabled ICMP stats recorder");
    let client_sequences = crate::net::icmp_sequence::SharedIcmpSequenceState::new();
    let upstream_sequences = crate::net::icmp_sequence::SharedIcmpSequenceState::new();
    let mut client_cache = client_sequences.cache();
    let mut upstream_cache = upstream_sequences.cache();
    crate::net::icmp_sequence::install_outbound_request_session(
        &upstream_sequences,
        &mut upstream_cache,
        crate::net::framing_shim::SessionId::new(17).expect("nonzero session ID"),
    )
    .expect("install active outbound request session before stable forwarding");
    let mut flow_snapshot_cache = crate::flow_state::FlowSnapshotCache::new();
    let mut cache = crate::worker_support::CachedClientState::new(true, 0, &cfg, &handles, false)
        .expect("initialize ICMP send cache");
    let started = Instant::now();

    let mut forward_once = || {
        let admitted = match crate::worker_support::packet_admission::admit_wire_packet(
            true,
            &cfg,
            receive_spec,
            b"stable",
            Some(&client_source),
        ) {
            Ok(admitted) => admitted,
            other => panic!("stable C2U packet was not admitted: {other:?}"),
        };
        let flow_read = flow_state
            .try_topology_read(crate::flow_state::FlowReaderLane::new(0))
            .expect("acquire active ICMP flow lane");
        let snapshot = flow_state
            .admission_snapshot_with_read(&flow_read, &mut flow_snapshot_cache, Instant::now())
            .expect("read active ICMP flow snapshot");
        let permit =
            crate::worker_support::StableForwardPermit::for_upstream(flow_read, snapshot, &handles);
        let decision = send_user_payload_event(
            &mut super::PacketContext::new(
                0,
                started,
                Instant::now(),
                &cfg,
                &mut recorder,
                &flow_state,
            ),
            &admitted.event,
            &handles,
            &mut cache,
            crate::worker_support::SequenceContext::new(
                &client_sequences,
                &mut client_cache,
                &upstream_sequences,
                &mut upstream_cache,
            ),
            None,
            permit,
        )
        .expect("forward active ICMP payload");
        assert!(matches!(
            decision,
            super::UserPayloadSendDecision::Sent {
                outcome: crate::net::session::HandledSendOutcome::Sent { .. },
                ..
            }
        ));
        delivery.record_send();
    };

    forward_once();
    let forbidden = crate::allocation_test_support::StableForwardAuthoritySnapshot::capture();
    let ((((), copies), candidates), allocations) =
        crate::allocation_test_support::count_allocations(|| {
            crate::allocation_test_support::count_lock_candidate_constructions(|| {
                crate::allocation_test_support::count_payload_copies(|| {
                    for _ in 0..COUNTED_PACKETS {
                        forward_once();
                    }
                })
            })
        });
    assert_eq!((allocations, copies, candidates), (0, 0, 0));
    forbidden.assert_unchanged();
    assert_eq!(
        receiving.join().expect("join ICMP frame sink"),
        TOTAL_PACKETS
    );
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
        9,
        100,
        BufferedPayload::from_event(&event, Some(dummy_trace)),
    );
    record_negotiation_sequence(&flow_state, 9);

    let ack_event = PayloadEvent::SessionControl {
        dst_proto: SupportedProtocol::ICMP,
        bytes: &[],
        icmp: crate::net::payload::IcmpPayloadMeta::new(
            5555,
            handles.upstream.upstream_local_filter.id(),
            9,
            crate::net::framing_shim::SessionId::for_tests(),
            crate::net::framing_shim::ReplyIdNegotiation::acknowledge(5555),
        ),
    };

    let result = observe_reply_id_ack(
        &cfg,
        &ack_event,
        &handles,
        &flow_state,
        Instant::now(),
        PacketTraceId {
            worker_id: 1,
            c2u: false,
            packet_id: 100,
        },
    );

    assert!(matches!(
        result,
        ObserveAckResult::Ignored {
            reason: crate::flow_state::ReplyIdHandshakeAckIgnored::WrongDestinationId { .. },
            trigger_trace,
            ..
        } if trigger_trace.packet_id == 100
    ));
    assert!(matches!(
        flow_state.ack_upstream_reply_id_handshake(1234, 9, 9, None),
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
        handles.upstream.upstream_local_filter.id(),
        10,
        100,
        BufferedPayload::from_event(&event, Some(buffered_trace)),
    );
    record_negotiation_sequence(&flow_state, 10);

    let ack_event = PayloadEvent::SessionControl {
        dst_proto: SupportedProtocol::ICMP,
        bytes: &[],
        icmp: crate::net::payload::IcmpPayloadMeta::new(
            7777,
            handles.upstream.upstream_local_filter.id(),
            10,
            crate::net::framing_shim::SessionId::new(10).expect("test session ID"),
            crate::net::framing_shim::ReplyIdNegotiation::acknowledge_instance(
                9999,
                crate::net::framing_shim::HandshakeInstance::new(10)
                    .expect("test handshake instance"),
            ),
        ),
    };
    let ack_trace = PacketTraceId {
        worker_id: 1,
        c2u: false,
        packet_id: 100,
    };

    let result = observe_reply_id_ack(
        &cfg,
        &ack_event,
        &handles,
        &flow_state,
        Instant::now(),
        ack_trace,
    );

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
    let mut stats = stats.recorder(0);
    let flow_state = FlowRuntimeState::new();
    let start = Instant::now();

    record_user_payload_route(
        &mut super::PacketContext::new(
            0,
            start,
            start + Duration::from_secs(4),
            &cfg,
            &mut stats,
            &flow_state,
        ),
        UserPayloadRoute::ForwardNow,
    );
    assert_eq!(
        flow_state.last_activity_tick_ns(),
        u64::try_from(Duration::from_secs(4).as_nanos()).expect("test duration fits")
    );

    let route = UserPayloadRoute::DropHandshakePending;
    record_user_payload_route(
        &mut super::PacketContext::new(
            0,
            start,
            start + Duration::from_secs(9),
            &cfg,
            &mut stats,
            &flow_state,
        ),
        route,
    );
    assert_eq!(
        flow_state.last_activity_tick_ns(),
        u64::try_from(Duration::from_secs(4).as_nanos()).expect("test duration fits"),
        "{route:?} must not refresh activity"
    );

    record_user_payload_route(
        &mut super::PacketContext::new(
            0,
            start,
            start + Duration::from_secs(7),
            &cfg,
            &mut stats,
            &flow_state,
        ),
        UserPayloadRoute::BufferFirstHandshakePayload,
    );
    assert_eq!(
        flow_state.last_activity_tick_ns(),
        u64::try_from(Duration::from_secs(7).as_nanos()).expect("test duration fits")
    );

    record_user_payload_route(
        &mut super::PacketContext::new(
            0,
            start,
            start + Duration::from_secs(8),
            &cfg,
            &mut stats,
            &flow_state,
        ),
        UserPayloadRoute::BufferSyncPayload,
    );
    assert_eq!(
        flow_state.last_activity_tick_ns(),
        u64::try_from(Duration::from_secs(8).as_nanos()).expect("test duration fits")
    );
}

#[test]
fn single_flow_activity_uses_direction_lanes_not_global_worker_ids() {
    let mut cfg = test_config(crate::cli::IcmpReplyIdRequest::Default);
    cfg.options.worker_flow_mode = crate::cli::WorkerFlowMode::SingleFlow;
    let stats = crate::stats::Stats::with_worker_shards(2);
    let mut client_stats = stats.recorder(0);
    let mut upstream_stats = stats.recorder(1);
    let flow_state = FlowRuntimeState::with_session_pool_size_and_reader_lanes(
        crate::cli::DEFAULT_ICMP_SESSION_POOL_SIZE,
        4,
    );
    let start = Instant::now();

    record_user_payload_route(
        &mut super::PacketContext::new(
            8,
            start,
            start + Duration::from_secs(4),
            &cfg,
            &mut client_stats,
            &flow_state,
        ),
        UserPayloadRoute::ForwardNow,
    );
    record_user_payload_route(
        &mut super::PacketContext::new(
            9,
            start,
            start + Duration::from_secs(6),
            &cfg,
            &mut upstream_stats,
            &flow_state,
        ),
        UserPayloadRoute::ForwardNow,
    );

    assert_eq!(
        flow_state.last_activity_tick_ns(),
        u64::try_from(Duration::from_secs(6).as_nanos()).expect("test duration fits")
    );
}

#[test]
fn bridge_forwarding_uses_the_destination_leg_session() {
    let flow_state = FlowRuntimeState::new();
    let upstream_session = crate::net::framing_shim::SessionId::new(22).expect("upstream session");
    let client_session = crate::net::framing_shim::SessionId::new(11).expect("client session");
    let buffered = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"first");
    flow_state.begin_upstream_reply_id_handshake(
        2002,
        upstream_session.get(),
        1,
        BufferedPayload::from_event(&buffered, None),
    );
    record_negotiation_sequence(&flow_state, 7);
    let crate::flow_state::ReplyIdHandshakeAck::Matched { token, .. } =
        flow_state.ack_upstream_reply_id_handshake(2002, upstream_session.get(), 7, None)
    else {
        panic!("activate upstream session");
    };
    flow_state
        .commit_upstream_reply_id_handshake(token)
        .expect("lease buffered payload");

    let inbound = PayloadEvent::icmp_user_payload(
        1001,
        1101,
        7,
        client_session,
        SupportedProtocol::ICMP,
        b"bridged",
    );
    assert_eq!(
        outbound_upstream_session_id(flow_state.upstream_session_id(), &inbound, None)
            .expect("destination session is active"),
        Some(upstream_session),
        "the inbound client session must not leak onto the upstream leg"
    );
}

#[test]
fn bridge_forwarding_never_falls_back_to_the_inbound_leg_session() {
    let flow_state = FlowRuntimeState::new();
    let inbound = PayloadEvent::icmp_user_payload(
        1001,
        1101,
        7,
        crate::net::framing_shim::SessionId::new(11).expect("client session"),
        SupportedProtocol::ICMP,
        b"bridged",
    );
    let error = outbound_upstream_session_id(flow_state.upstream_session_id(), &inbound, None)
        .expect_err("an inactive destination leg must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn deferred_sync_result_does_not_claim_payload_ownership() {
    let now = Instant::now();
    let deferred = super::deferred_payload_send_result(now);
    assert!(!deferred.transferred_payload_ownership());

    let retained = super::PayloadSendResult {
        retained_recovery_payload: true,
        ..deferred
    };
    assert!(retained.transferred_payload_ownership());
}
