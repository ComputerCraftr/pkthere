use super::{UpstreamForwardOutcome, UpstreamWorkerContext, process_admitted_upstream_event};
use crate::allocation_test_support_tests::ExactDatagramDeliveryProgress;
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::flow_state::PendingIcmpClientLock;
use crate::flow_state::{FlowReaderLane, FlowRuntimeState, FlowSnapshotCache};
use crate::net::framing_shim::{SessionId, SessionKey};
use crate::net::icmp_sequence::SharedIcmpSequenceState;
use crate::runtime_support::ShutdownController;
use crate::worker_support::admission_test_support::{synthetic_receive_context, test_config};
use crate::worker_support::test_support::{forwarding_handles, unused_manager};
use crate::worker_support::{CachedClientState, PacketTraceId, SocketLeg};
use pkthere_socket_policy::{PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy};
use socket2::Type;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn locked_udp_u2c_production_send_path_is_allocation_copy_and_global_authority_free() {
    const COUNTED_PACKETS: usize = 10_000;
    const TOTAL_PACKETS: usize = COUNTED_PACKETS + 1;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP client sink");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set client sink timeout");
    let client_address = client.local_addr().expect("client sink address");
    let (mut delivery, received_count) = ExactDatagramDeliveryProgress::new();
    let receiving = std::thread::spawn(move || {
        let mut payload = [0_u8; 16];
        let mut received = 0;
        while received < TOTAL_PACKETS {
            let (length, _) = client
                .recv_from(&mut payload)
                .expect("receive every U2C payload");
            assert_eq!(&payload[..length], b"stable");
            received += 1;
            ExactDatagramDeliveryProgress::record_receive(&received_count, received);
        }
        received
    });
    let upstream_peer =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream source metadata peer");
    let upstream_peer_address = upstream_peer.local_addr().expect("upstream peer address");
    let handles = forwarding_handles(
        SupportedProtocol::UDP,
        client_address,
        upstream_peer_address,
    );
    let manager = Arc::new(unused_manager(upstream_peer_address));
    let managers = [Arc::clone(&manager)];
    let mut cfg = test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    cfg.upstream_proto = SupportedProtocol::UDP;
    let client_endpoint = LogicalEndpoint::from_socket_addr(client_address);
    let flow_key = ClientFlowKey::Udp(client_endpoint);
    let flow_state = FlowRuntimeState::new();
    flow_state
        .reserve_client_flow()
        .publish_locked(flow_key)
        .expect("publish stable U2C UDP flow");
    let stats = crate::stats::Stats::new(1, false).expect("disabled test stats");
    let mut recorder = stats.try_recorder(0).expect("disabled stats recorder");
    let client_sequences = SharedIcmpSequenceState::new();
    let upstream_sequences = SharedIcmpSequenceState::new();
    let mut client_sequence_cache = client_sequences.cache();
    let shutdown = ShutdownController::new(1).expect("shutdown controller");
    let mut context = UpstreamWorkerContext {
        t_start: Instant::now(),
        cfg: &cfg,
        sock_mgr: &manager,
        all_sock_mgrs: &managers,
        worker_id: 0,
        flow_lane: FlowReaderLane::new(0),
        flow_state: &flow_state,
        stats: &mut recorder,
        client_side_state: &client_sequences,
        upstream_side_state: &upstream_sequences,
        exit_code_set: &shutdown,
    };
    let upstream_source = socket2::SockAddr::from(upstream_peer_address);
    let upstream_local = handles.upstream.upstream_local_filter;
    let mut receive_spec = synthetic_receive_context(
        SocketLeg::UpstreamFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::None,
        },
        Some(LogicalEndpoint::from_socket_addr(upstream_peer_address)),
        Some(upstream_local.id()),
        Some(upstream_local.ip()),
    );
    receive_spec.admission.locked_flow = Some(flow_key);
    let mut cache = CachedClientState::new(false, 0, &cfg, &handles, false)
        .expect("initialize UDP listener-send cache");
    let mut flow_snapshot_cache = FlowSnapshotCache::new();

    let mut forward_once = |packet_id| {
        let admitted = match crate::worker_support::admit_wire_packet(
            false,
            &cfg,
            receive_spec,
            b"stable",
            Some(&upstream_source),
        ) {
            Ok(admitted) => admitted,
            other => panic!("stable U2C UDP packet was not admitted: {other:?}"),
        };
        let flow_read = flow_state
            .try_topology_read(FlowReaderLane::new(0))
            .expect("acquire U2C flow lane");
        let flow_snapshot = *flow_state
            .admission_snapshot_with_read(&flow_read, &mut flow_snapshot_cache, Instant::now())
            .expect("read production U2C flow snapshot");
        let outcome = process_admitted_upstream_event(
            &mut context,
            &handles,
            &mut cache,
            &mut client_sequence_cache,
            flow_read,
            flow_snapshot.for_packet(None),
            &admitted.event,
            PacketTraceId {
                worker_id: 0,
                c2u: false,
                packet_id,
            },
            Instant::now(),
        );
        assert!(matches!(outcome, UpstreamForwardOutcome::Continue));
        delivery.record_send();
    };

    forward_once(0);
    let forbidden = crate::allocation_test_support::StableForwardAuthoritySnapshot::capture();
    let (((), copies), allocations) = crate::allocation_test_support::count_allocations(|| {
        crate::allocation_test_support::count_payload_copies(|| {
            for packet_id in 1..=COUNTED_PACKETS as u64 {
                forward_once(packet_id);
            }
        })
    });
    assert_eq!(allocations, 0);
    assert_eq!(copies, 0);
    forbidden.assert_unchanged();
    assert_eq!(receiving.join().expect("join U2C UDP sink"), TOTAL_PACKETS);
}

#[test]
fn active_icmp_u2c_production_send_path_is_allocation_copy_and_global_authority_free() {
    const COUNTED_PACKETS: usize = 10_000;
    const TOTAL_PACKETS: usize = COUNTED_PACKETS + 1;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ICMP client sink");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set ICMP client sink timeout");
    let client_address = client.local_addr().expect("ICMP client sink address");
    let (mut delivery, received_count) = ExactDatagramDeliveryProgress::new();
    let receiving = std::thread::spawn(move || {
        let mut packet = [0_u8; 128];
        let mut received = 0;
        while received < TOTAL_PACKETS {
            let (length, _) = client
                .recv_from(&mut packet)
                .expect("receive every U2C ICMP frame");
            assert!(length > b"stable".len());
            assert!(packet[..length].ends_with(b"stable"));
            received += 1;
            ExactDatagramDeliveryProgress::record_receive(&received_count, received);
        }
        received
    });
    let upstream_peer =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ICMP upstream source peer");
    let upstream_peer_address = upstream_peer
        .local_addr()
        .expect("ICMP upstream peer address");
    let handles = forwarding_handles(
        SupportedProtocol::ICMP,
        client_address,
        upstream_peer_address,
    );
    let manager = Arc::new(unused_manager(upstream_peer_address));
    let managers = [Arc::clone(&manager)];
    let mut cfg = test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::ICMP;
    cfg.upstream_proto = SupportedProtocol::ICMP;
    let client_endpoint = LogicalEndpoint::from_socket_addr(client_address);
    let listener_endpoint = handles.listener.listen_local_filter;
    let session = SessionId::for_tests();
    let session_key = SessionKey::initial(session).expect("initial client session key");
    let flow_key = ClientFlowKey::Icmp(client_endpoint);
    let pending = PendingIcmpClientLock {
        flow_key,
        session_key: Some(session_key),
        observed_control: Some(crate::flow_state::PendingClientControl::Negotiate {
            reply_id: client_endpoint.id(),
        }),
        reset_challenge: 0,
        reset_evidence: None,
        listener_flow: SocketLegFlow::new(
            Some(FlowTuple::new(client_endpoint, listener_endpoint)),
            Some(FlowTuple::new(listener_endpoint, client_endpoint)),
        ),
    };
    let flow_state = FlowRuntimeState::new();
    flow_state
        .set_pending_icmp_client_lock(
            pending,
            1,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            37,
        )
        .expect("install client ICMP session");
    flow_state
        .reserve_client_flow()
        .publish_locked(flow_key)
        .expect("publish client ICMP flow");
    let stats = crate::stats::Stats::new(1, false).expect("disabled ICMP test stats");
    let mut recorder = stats.try_recorder(0).expect("disabled ICMP stats recorder");
    let client_sequences = SharedIcmpSequenceState::new();
    let upstream_sequences = SharedIcmpSequenceState::new();
    let mut client_sequence_cache = client_sequences.cache();
    crate::net::icmp_sequence::activate_receive_session(
        &client_sequences,
        &mut client_sequence_cache,
        session,
    );
    crate::net::icmp_sequence::activate_receive_session(
        &upstream_sequences,
        &mut upstream_sequences.cache(),
        session,
    );
    let client_request = crate::net::payload::PayloadEvent::icmp_user_payload(
        client_endpoint.id(),
        listener_endpoint.id(),
        37,
        session,
        SupportedProtocol::ICMP,
        b"request",
    );
    crate::net::payload::classify_c2u_data_or_cadence_event(
        &client_request,
        &client_sequences,
        &mut client_sequence_cache,
    )
    .expect("remember client request sequence for U2C replies");
    let shutdown = ShutdownController::new(1).expect("shutdown controller");
    let mut context = UpstreamWorkerContext {
        t_start: Instant::now(),
        cfg: &cfg,
        sock_mgr: &manager,
        all_sock_mgrs: &managers,
        worker_id: 0,
        flow_lane: FlowReaderLane::new(0),
        flow_state: &flow_state,
        stats: &mut recorder,
        client_side_state: &client_sequences,
        upstream_side_state: &upstream_sequences,
        exit_code_set: &shutdown,
    };
    let upstream_endpoint = handles.upstream.upstream_remote_filter;
    let upstream_local = handles.upstream.upstream_local_filter;
    let upstream_source = socket2::SockAddr::from(upstream_peer_address);
    let mut receive_spec = synthetic_receive_context(
        SocketLeg::UpstreamFacing,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        Some(upstream_endpoint),
        Some(upstream_local.id()),
        Some(upstream_local.ip()),
    );
    receive_spec.admission.locked_flow = Some(flow_key);
    receive_spec.admission.expected_session_id = Some(session);
    let mut packet = crate::worker_support::admission_test_support::icmp_data_packet(
        upstream_local.id(),
        false,
        upstream_endpoint.id(),
        b"stable",
    );
    let mut cache = CachedClientState::new(false, 0, &cfg, &handles, false)
        .expect("initialize ICMP listener-send cache");
    let mut flow_snapshot_cache = FlowSnapshotCache::new();

    let mut forward_once = |packet_id: u64, sequence: u16| {
        packet[6..8].copy_from_slice(&sequence.to_be_bytes());
        let admitted = match crate::worker_support::admit_wire_packet(
            false,
            &cfg,
            receive_spec,
            &packet,
            Some(&upstream_source),
        ) {
            Ok(admitted) => admitted,
            other => panic!("active U2C ICMP packet was not admitted: {other:?}"),
        };
        let flow_read = flow_state
            .try_topology_read(FlowReaderLane::new(0))
            .expect("acquire U2C ICMP flow lane");
        let flow_snapshot = *flow_state
            .admission_snapshot_with_read(&flow_read, &mut flow_snapshot_cache, Instant::now())
            .expect("read production U2C ICMP flow snapshot");
        let outcome = process_admitted_upstream_event(
            &mut context,
            &handles,
            &mut cache,
            &mut client_sequence_cache,
            flow_read,
            flow_snapshot.for_packet(Some(session)),
            &admitted.event,
            PacketTraceId {
                worker_id: 0,
                c2u: false,
                packet_id,
            },
            Instant::now(),
        );
        assert!(matches!(outcome, UpstreamForwardOutcome::Continue));
        delivery.record_send();
    };

    forward_once(0, 0);
    let forbidden = crate::allocation_test_support::StableForwardAuthoritySnapshot::capture();
    let (((), copies), allocations) = crate::allocation_test_support::count_allocations(|| {
        crate::allocation_test_support::count_payload_copies(|| {
            for sequence in 1..=COUNTED_PACKETS as u16 {
                forward_once(u64::from(sequence), sequence);
            }
        })
    });
    assert_eq!((allocations, copies), (0, 0));
    forbidden.assert_unchanged();
    assert_eq!(receiving.join().expect("join U2C ICMP sink"), TOTAL_PACKETS);
}
