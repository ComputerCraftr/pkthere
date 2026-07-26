#![cfg(all(test, not(miri)))]

use super::upstream::{
    UpstreamForwardOutcome, UpstreamWorkerContext, process_admitted_upstream_event,
};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::flow_state::{
    FlowReaderLane, FlowRuntimeState, FlowSnapshotCache, PendingIcmpClientLock,
};
use crate::net::framing_shim::{SessionId, SessionKey};
use crate::net::icmp_sequence::SharedIcmpSequenceState;
use crate::net::payload::PayloadEvent;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use crate::runtime_support::ShutdownController;
use crate::worker_support::dispatch::UserPayloadSendDecision;
use crate::worker_support::pipeline_audit::{
    TestPipelinePause, TestPipelineSuiteGuard, TestPipelineThreadToken,
};
use crate::worker_support::test_support::{
    activate_upstream_session_for_forwarding, forwarding_handles, unused_manager,
};
use crate::worker_support::{CachedClientState, PacketTraceId, PipelineStage};
use crate::worker_support::{
    ClientWorkerContext, run_client_to_upstream_thread, run_upstream_to_client_thread,
};
use pkthere_socket_policy::{ProtocolPolicyIntent, SocketRole, listener_worker_socket_policy};
use socket2::{Domain, Type};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SEND_STAGES: [PipelineStage; 5] = [
    PipelineStage::SnapshotValidated,
    PipelineStage::DestinationSocketAcquired,
    PipelineStage::SequenceReserved,
    PipelineStage::BeforeSend,
    PipelineStage::AfterSend,
];
const COMPLETE_PIPELINE_STAGES: [PipelineStage; 8] = [
    PipelineStage::FlowLaneAcquired,
    PipelineStage::SnapshotValidated,
    PipelineStage::ReceiveCompleted,
    PipelineStage::ReplayAdmitted,
    PipelineStage::DestinationSocketAcquired,
    PipelineStage::SequenceReserved,
    PipelineStage::BeforeSend,
    PipelineStage::AfterSend,
];
const PIPELINE_TIMEOUT: Duration = Duration::from_secs(2);

struct OverlapContext<'a> {
    protocol: SupportedProtocol,
    session: Option<SessionId>,
    cfg: &'a crate::cli::RuntimeConfig,
    handles: &'a SocketHandles,
    manager: &'a Arc<SocketManager>,
    managers: &'a [Arc<SocketManager>],
    flow_state: &'a FlowRuntimeState,
    client_sequences: &'a SharedIcmpSequenceState,
    upstream_sequences: &'a SharedIcmpSequenceState,
    shutdown: &'a ShutdownController,
}

impl OverlapContext<'_> {
    fn run_c2u(&self, stats: &mut crate::stats::StatsRecorder) {
        let mut cache = CachedClientState::new(true, 0, self.cfg, self.handles, false)
            .expect("initialize C2U overlap descriptor cache");
        let mut client_cache = self.client_sequences.cache();
        let mut upstream_cache = self.upstream_sequences.cache();
        if let Some(session) = self.session {
            crate::net::icmp_sequence::load_installed_outbound_session(
                self.upstream_sequences,
                &mut upstream_cache,
                session,
            )
            .expect("refresh C2U overlap transmit cache before flow authority");
        }
        let mut snapshot_cache = FlowSnapshotCache::new();
        let flow_read = self
            .flow_state
            .try_topology_read(FlowReaderLane::new(0))
            .expect("C2U overlap flow lane");
        let snapshot = self
            .flow_state
            .admission_snapshot_with_read(&flow_read, &mut snapshot_cache, Instant::now())
            .expect("C2U overlap snapshot");
        let permit = crate::worker_support::StableForwardPermit::for_upstream(
            flow_read,
            snapshot,
            self.handles,
        );
        let event = PayloadEvent::user_payload_plain(self.protocol, b"c2u");
        let decision = crate::worker_support::send_user_payload_event(
            &mut crate::worker_support::PacketContext::new(
                0,
                Instant::now(),
                Instant::now(),
                self.cfg,
                stats,
                self.flow_state,
            ),
            &event,
            self.handles,
            &mut cache,
            crate::worker_support::SequenceContext::new(
                self.client_sequences,
                &mut client_cache,
                self.upstream_sequences,
                &mut upstream_cache,
            ),
            None,
            permit,
        )
        .expect("C2U overlap production send");
        assert!(matches!(decision, UserPayloadSendDecision::Sent { .. }));
    }

    fn run_u2c(&self, stats: &mut crate::stats::StatsRecorder, sequence: u16) {
        let mut context = UpstreamWorkerContext {
            t_start: Instant::now(),
            cfg: self.cfg,
            sock_mgr: self.manager,
            all_sock_mgrs: self.managers,
            worker_id: 1,
            flow_lane: FlowReaderLane::new(1),
            flow_state: self.flow_state,
            stats,
            client_side_state: self.client_sequences,
            upstream_side_state: self.upstream_sequences,
            exit_code_set: self.shutdown,
        };
        let mut cache = CachedClientState::new(false, 1, self.cfg, self.handles, false)
            .expect("initialize U2C overlap descriptor cache");
        let mut client_cache = self.client_sequences.cache();
        if let Some(session) = self.session {
            crate::net::icmp_sequence::load_installed_outbound_session(
                self.client_sequences,
                &mut client_cache,
                session,
            )
            .expect("refresh U2C overlap transmit cache before flow authority");
        }
        let mut snapshot_cache = FlowSnapshotCache::new();
        let flow_read = self
            .flow_state
            .try_topology_read(FlowReaderLane::new(1))
            .expect("U2C overlap flow lane");
        let snapshot = *self
            .flow_state
            .admission_snapshot_with_read(&flow_read, &mut snapshot_cache, Instant::now())
            .expect("U2C overlap snapshot");
        let event = self.session.map_or_else(
            || PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"u2c"),
            |session| {
                PayloadEvent::icmp_user_payload(
                    self.handles.upstream.upstream_local_filter.id(),
                    self.handles.upstream.upstream_remote_filter.id(),
                    sequence,
                    session,
                    SupportedProtocol::ICMP,
                    b"u2c",
                )
            },
        );
        let outcome = process_admitted_upstream_event(
            &mut context,
            self.handles,
            &mut cache,
            &mut client_cache,
            flow_read,
            snapshot.for_packet(self.session),
            &event,
            PacketTraceId {
                worker_id: 1,
                c2u: false,
                packet_id: u64::from(sequence),
            },
            Instant::now(),
        );
        assert!(matches!(outcome, UpstreamForwardOutcome::Continue));
    }
}

fn configure_icmp_flow(
    flow_state: &FlowRuntimeState,
    handles: &SocketHandles,
    client: LogicalEndpoint,
    session: SessionId,
) {
    let flow_key = ClientFlowKey::Icmp(client);
    let session_key = SessionKey::initial(session).expect("initial session key");
    flow_state
        .set_pending_icmp_client_lock(
            PendingIcmpClientLock {
                flow_key,
                session_key: Some(session_key),
                observed_control: Some(crate::flow_state::PendingClientControl::Negotiate {
                    reply_id: client.id(),
                }),
                reset_challenge: 0,
                reset_evidence: None,
                listener_flow: SocketLegFlow::new(
                    Some(FlowTuple::new(client, handles.listener.listen_local_filter)),
                    Some(FlowTuple::new(handles.listener.listen_local_filter, client)),
                ),
            },
            1,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            37,
        )
        .expect("install overlap client session");
    flow_state
        .reserve_client_flow()
        .publish_locked(flow_key)
        .expect("publish overlap ICMP flow");
    activate_upstream_session_for_forwarding(flow_state, session.get());
}

fn prove_bidirectional_send_overlap(protocol: SupportedProtocol) {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind overlap client sink");
    let client_address = client.local_addr().expect("overlap client address");
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind overlap upstream sink");
    let upstream_address = upstream.local_addr().expect("overlap upstream address");
    let handles = forwarding_handles(protocol, client_address, upstream_address);
    let manager = Arc::new(unused_manager(upstream_address));
    let managers = [Arc::clone(&manager)];
    let mut cfg =
        crate::worker_support::admission_test_support::test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = protocol;
    cfg.upstream_proto = protocol;
    let flow_state = FlowRuntimeState::new();
    let client_endpoint = LogicalEndpoint::from_socket_addr(client_address);
    let session = (protocol == SupportedProtocol::ICMP)
        .then(|| SessionId::new(17).expect("nonzero overlap session"));
    if let Some(session) = session {
        configure_icmp_flow(&flow_state, &handles, client_endpoint, session);
    } else {
        flow_state
            .reserve_client_flow()
            .publish_locked(ClientFlowKey::Udp(client_endpoint))
            .expect("publish overlap UDP flow");
    }
    let stats = crate::stats::Stats::new(2, false).expect("disabled overlap stats");
    let shutdown = ShutdownController::new(2).expect("overlap shutdown controller");
    let client_sequences = SharedIcmpSequenceState::new();
    let upstream_sequences = SharedIcmpSequenceState::new();
    if let Some(session) = session {
        crate::net::icmp_sequence::activate_receive_session(
            &client_sequences,
            &mut client_sequences.cache(),
            session,
        );
        crate::net::icmp_sequence::activate_receive_session(
            &upstream_sequences,
            &mut upstream_sequences.cache(),
            session,
        );
        crate::net::icmp_sequence::install_outbound_request_session(
            &client_sequences,
            &mut client_sequences.cache(),
            session,
        )
        .expect("prepare U2C overlap transmit session");
        crate::net::icmp_sequence::install_outbound_request_session(
            &upstream_sequences,
            &mut upstream_sequences.cache(),
            session,
        )
        .expect("prepare C2U overlap transmit session");
    }
    let overlap = OverlapContext {
        protocol,
        session,
        cfg: &cfg,
        handles: &handles,
        manager: &manager,
        managers: &managers,
        flow_state: &flow_state,
        client_sequences: &client_sequences,
        upstream_sequences: &upstream_sequences,
        shutdown: &shutdown,
    };

    for (index, (paused_c2u, stage)) in [true, false]
        .into_iter()
        .flat_map(|direction| SEND_STAGES.map(|stage| (direction, stage)))
        .enumerate()
    {
        let sequence = u16::try_from(index + 1).expect("bounded overlap sequence");
        let overlap_ref = &overlap;
        let mut pause =
            TestPipelinePause::arm(paused_c2u, stage).expect("arm production pipeline barrier");
        std::thread::scope(|scope| {
            let (other_done_tx, other_done_rx) = std::sync::mpsc::sync_channel(1);
            let token = pause.token();
            let mut paused_stats = stats
                .try_recorder(usize::from(!paused_c2u))
                .expect("paused overlap recorder");
            let paused = scope.spawn(move || {
                let token_guard = TestPipelineThreadToken::install(token);
                if paused_c2u {
                    overlap_ref.run_c2u(&mut paused_stats);
                } else {
                    overlap_ref.run_u2c(&mut paused_stats, sequence);
                }
                drop(token_guard);
            });
            assert!(
                pause.wait_until_arrived(Duration::from_secs(1)),
                "{protocol:?} {stage:?} did not retain the production pipeline"
            );
            let mut progressing_stats = stats
                .try_recorder(usize::from(paused_c2u))
                .expect("progressing overlap recorder");
            scope.spawn(move || {
                if paused_c2u {
                    overlap_ref.run_u2c(&mut progressing_stats, sequence);
                } else {
                    overlap_ref.run_c2u(&mut progressing_stats);
                }
                other_done_tx.send(()).expect("report opposite progress");
            });
            let progressed = other_done_rx.recv_timeout(Duration::from_secs(1));
            pause.release();
            assert!(
                progressed.is_ok(),
                "{protocol:?} opposite direction could not pass {stage:?}"
            );
            paused.join().expect("paused production direction");
        });
    }
}

fn unconnected_pipeline_manager(
    protocol: SupportedProtocol,
    upstream_peer: std::net::SocketAddr,
) -> SocketManager {
    let client_sock = crate::worker_support::test_support::udp_socket();
    let listener_address = client_sock
        .local_addr()
        .expect("pipeline listener address")
        .as_socket()
        .expect("pipeline listener IP address");
    let upstream_sock = crate::worker_support::test_support::udp_socket();
    let upstream_local_address = upstream_sock
        .local_addr()
        .expect("pipeline upstream socket address")
        .as_socket()
        .expect("pipeline upstream socket IP address");
    let intent = match protocol {
        SupportedProtocol::UDP => ProtocolPolicyIntent::Udp,
        SupportedProtocol::ICMP => {
            ProtocolPolicyIntent::Icmp(pkthere_socket_policy::IcmpPolicyIntent::default())
        }
    };
    let listener_policy = pkthere_socket_policy::resolve_socket_policy_with_protocol_intent(
        SocketRole::Listener,
        intent,
        Type::DGRAM,
        crate::cli::TimeoutAction::Drop,
        true,
        Domain::IPV4,
    );
    let upstream_policy = pkthere_socket_policy::resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        intent,
        Type::DGRAM,
        crate::cli::TimeoutAction::Drop,
        true,
        Domain::IPV4,
    );
    let init = crate::net::sock_mgr::SocketManagerInit {
        socket_slot: 0,
        worker_io_lanes: crate::worker_support::descriptor_cache_lane_count(1)
            .expect("one worker-pair descriptor-cache capacity"),
        client_sock,
        listen_local_filter: LogicalEndpoint::from_socket_addr(listener_address),
        listen_local_kernel_addr: listener_address,
        listen_sock_type: Type::DGRAM,
        listen_target: listener_address.to_string(),
        listen_proto: protocol,
        listen_policy: listener_policy,
        listen_worker_socket_policy: listener_worker_socket_policy(1, false),
        listen_debug_unconnected: true,
        upstream_remote_filter: LogicalEndpoint::from_socket_addr(upstream_peer),
        upstream_target: upstream_peer.to_string(),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: protocol,
        upstream_debug_unconnected: true,
        upstream_icmp_kernel_echo_self_handshake: false,
        upstream_worker_socket_policy: Default::default(),
        shared_upstream_identity: None,
        force_raw_icmp_wildcard_upstream: false,
        timeout_act: crate::cli::TimeoutAction::Drop,
        debug_handles: false,
    };
    SocketManager::from_realized_upstream(
        init,
        crate::net::socket::RealizedUpstreamSocket {
            socket: upstream_sock,
            local_filter: LogicalEndpoint::from_socket_addr(upstream_local_address),
            remote_filter: LogicalEndpoint::from_socket_addr(upstream_peer),
            local_kernel_addr: upstream_local_address,
            socket_type: Type::DGRAM,
            policy: upstream_policy,
        },
    )
    .expect("create unconnected UDP pipeline manager")
}

fn publish_pipeline_flow(
    manager: &SocketManager,
    flow_state: &FlowRuntimeState,
    client: std::net::SocketAddr,
    protocol: SupportedProtocol,
) -> SocketHandles {
    let initial = manager
        .capture_startup_handles()
        .expect("initial pipeline handles");
    let client_endpoint = LogicalEndpoint::from_socket_addr(client);
    let listener = initial.listener.listen_local_filter;
    let flow = match protocol {
        SupportedProtocol::UDP => ClientFlowKey::Udp(client_endpoint),
        SupportedProtocol::ICMP => ClientFlowKey::Icmp(client_endpoint),
    };
    let prepared = SocketManager::prepare_client_flow_group(
        &[manager],
        crate::net::sock_mgr::ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::new(
                Some(FlowTuple::new(client_endpoint, listener)),
                Some(FlowTuple::new(listener, client_endpoint)),
            ),
            admitting_listener_slot: manager.socket_slot(),
            client,
        },
    )
    .expect("prepare pipeline flow");
    let mut transaction = flow_state.reserve_client_flow();
    let transition = SocketManager::begin_client_flow_group_transition(prepared, &mut transaction)
        .expect("begin pipeline flow transition");
    let mut updates = transition.publish(None).expect("publish pipeline flow");
    assert_eq!(updates.len(), 1);
    updates.pop().expect("one pipeline manager update").handles
}

fn receive_exact(socket: &UdpSocket, expected: &[u8]) {
    let mut payload = [0_u8; 64];
    let (length, _) = socket
        .recv_from(&mut payload)
        .expect("receive pipeline payload");
    assert_eq!(&payload[..length], expected);
}

fn receive_icmp_payload(socket: &UdpSocket, expected: &[u8]) -> std::io::Result<bool> {
    let mut packet = [0_u8; 512];
    loop {
        let (length, _) = socket.recv_from(&mut packet)?;
        if packet[..length].ends_with(expected) {
            return Ok(true);
        }
    }
}

fn prove_udp_complete_pipeline_overlap(paused_c2u: bool, stage: PipelineStage) {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind pipeline client");
    client
        .set_read_timeout(Some(PIPELINE_TIMEOUT))
        .expect("set pipeline client timeout");
    let client_address = client.local_addr().expect("pipeline client address");
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind pipeline upstream");
    upstream
        .set_read_timeout(Some(PIPELINE_TIMEOUT))
        .expect("set pipeline upstream timeout");
    let upstream_address = upstream.local_addr().expect("pipeline upstream address");
    let manager = Arc::new(unconnected_pipeline_manager(
        SupportedProtocol::UDP,
        upstream_address,
    ));
    let managers = [Arc::clone(&manager)];
    let flow_state = FlowRuntimeState::new();
    let handles = publish_pipeline_flow(
        &manager,
        &flow_state,
        client_address,
        SupportedProtocol::UDP,
    );
    let listener_address = handles.listener.listen_local_kernel_addr;
    let upstream_local_address = handles.upstream.upstream_local_kernel_addr;
    let mut cfg =
        crate::worker_support::admission_test_support::test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    cfg.upstream_proto = SupportedProtocol::UDP;
    let stats = crate::stats::Stats::new(2, false).expect("disabled pipeline stats");
    let mut c2u_stats = stats.try_recorder(0).expect("pipeline C2U recorder");
    let mut u2c_stats = stats.try_recorder(1).expect("pipeline U2C recorder");
    let shutdown = ShutdownController::new(2).expect("pipeline shutdown controller");
    let client_sequences = SharedIcmpSequenceState::new();
    let upstream_sequences = SharedIcmpSequenceState::new();
    let mut pause =
        TestPipelinePause::arm(paused_c2u, stage).expect("arm complete pipeline barrier");
    let token = pause.token();

    std::thread::scope(|scope| {
        let cfg_ref = &cfg;
        let manager_ref = &manager;
        let managers_ref = &managers;
        let flow_state_ref = &flow_state;
        let client_sequences_ref = &client_sequences;
        let upstream_sequences_ref = &upstream_sequences;
        let shutdown_ref = &shutdown;
        let c2u = scope.spawn(move || {
            let token_guard = paused_c2u.then(|| TestPipelineThreadToken::install(token));
            run_client_to_upstream_thread(ClientWorkerContext {
                t_start: Instant::now(),
                cfg: cfg_ref,
                sock_mgr: manager_ref,
                all_sock_mgrs: managers_ref,
                worker_id: 0,
                flow_lane: FlowReaderLane::new(0),
                flow_state: flow_state_ref,
                stats: &mut c2u_stats,
                client_side_state: client_sequences_ref,
                upstream_side_state: upstream_sequences_ref,
                sync_pacer: None,
                flow_claims: None,
                worker_pair_id: 0,
                exit_code_set: shutdown_ref,
            });
            drop(token_guard);
        });
        let u2c = scope.spawn(move || {
            let token_guard = (!paused_c2u).then(|| TestPipelineThreadToken::install(token));
            run_upstream_to_client_thread(UpstreamWorkerContext {
                t_start: Instant::now(),
                cfg: cfg_ref,
                sock_mgr: manager_ref,
                all_sock_mgrs: managers_ref,
                worker_id: 1,
                flow_lane: FlowReaderLane::new(1),
                flow_state: flow_state_ref,
                stats: &mut u2c_stats,
                client_side_state: client_sequences_ref,
                upstream_side_state: upstream_sequences_ref,
                exit_code_set: shutdown_ref,
            });
            drop(token_guard);
        });

        let (paused_source, paused_destination, paused_payload) = if paused_c2u {
            (&client, listener_address, b"paused-c2u".as_slice())
        } else {
            (&upstream, upstream_local_address, b"paused-u2c".as_slice())
        };
        paused_source
            .send_to(paused_payload, paused_destination)
            .expect("send paused pipeline packet");
        assert!(
            pause.wait_until_arrived(PIPELINE_TIMEOUT),
            "paused UDP direction did not reach {stage:?}"
        );

        if paused_c2u {
            upstream
                .send_to(b"progress-u2c", upstream_local_address)
                .expect("send progressing U2C packet");
            receive_exact(&client, b"progress-u2c");
        } else {
            client
                .send_to(b"progress-c2u", listener_address)
                .expect("send progressing C2U packet");
            receive_exact(&upstream, b"progress-c2u");
        }

        pause.release();
        if paused_c2u {
            receive_exact(&upstream, paused_payload);
        } else {
            receive_exact(&client, paused_payload);
        }
        shutdown_ref.request_graceful(0);
        c2u.join().expect("join complete pipeline C2U worker");
        u2c.join().expect("join complete pipeline U2C worker");
    });
}

struct IcmpPipelineState {
    handles: SocketHandles,
    cfg: crate::cli::RuntimeConfig,
    session: SessionId,
    upstream_receive_session: SessionId,
    client_endpoint: LogicalEndpoint,
}

fn configure_icmp_pipeline(
    manager: &SocketManager,
    flow_state: &FlowRuntimeState,
    client_sequences: &SharedIcmpSequenceState,
    upstream_sequences: &SharedIcmpSequenceState,
    client_address: std::net::SocketAddr,
    upstream_address: std::net::SocketAddr,
) -> IcmpPipelineState {
    let session = SessionId::new(17).expect("nonzero ICMP pipeline session");
    let initial = manager
        .capture_startup_handles()
        .expect("initial ICMP pipeline handles");
    let client_endpoint = LogicalEndpoint::from_socket_addr(client_address);
    let session_key = SessionKey::initial(session).expect("initial ICMP pipeline session key");
    flow_state
        .set_pending_icmp_client_lock(
            PendingIcmpClientLock {
                flow_key: ClientFlowKey::Icmp(client_endpoint),
                session_key: Some(session_key),
                observed_control: Some(crate::flow_state::PendingClientControl::Negotiate {
                    reply_id: client_endpoint.id(),
                }),
                reset_challenge: 0,
                reset_evidence: None,
                listener_flow: SocketLegFlow::new(
                    Some(FlowTuple::new(
                        client_endpoint,
                        initial.listener.listen_local_filter,
                    )),
                    Some(FlowTuple::new(
                        initial.listener.listen_local_filter,
                        client_endpoint,
                    )),
                ),
            },
            1,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            37,
        )
        .expect("install ICMP pipeline candidate");
    let handles =
        publish_pipeline_flow(manager, flow_state, client_address, SupportedProtocol::ICMP);
    let mut cfg =
        crate::worker_support::admission_test_support::test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::ICMP;
    cfg.upstream_proto = SupportedProtocol::ICMP;
    flow_state
        .mark_client_candidate_acknowledged(session_key, Instant::now())
        .expect("mark ICMP pipeline candidate ready");
    let transition = flow_state.reserve_client_flow();
    flow_state
        .promote_ready_icmp_client_session_with_replay_under(
            &transition,
            session,
            Instant::now() + Duration::from_secs(3),
            client_sequences,
            &mut client_sequences.cache(),
        )
        .expect("promote ICMP pipeline receive session");
    drop(transition);
    crate::net::icmp_sequence::activate_receive_session(
        client_sequences,
        &mut client_sequences.cache(),
        session,
    );
    activate_upstream_session_for_forwarding(flow_state, session.get());
    let admission_snapshot = flow_state.admission_snapshot(Instant::now());
    assert_eq!(admission_snapshot.client_receive_session_id, Some(session));
    assert!(admission_snapshot.upstream_reply_id_acked);
    assert!(admission_snapshot.upstream_transmit_session_id.is_some());
    assert_eq!(
        client_sequences.receive_session_id_for_tests(),
        Some(session)
    );
    let upstream_receive_session = admission_snapshot
        .upstream_receive_session_id
        .expect("ICMP pipeline upstream receive session was not active");
    let client_transmit_session = admission_snapshot
        .client_transmit_session_id
        .expect("ICMP pipeline client transmit session was not active");
    let upstream_transmit_session = admission_snapshot
        .upstream_transmit_session_id
        .expect("ICMP pipeline upstream transmit session was not active");
    crate::net::icmp_sequence::install_outbound_request_session(
        client_sequences,
        &mut client_sequences.cache(),
        client_transmit_session,
    )
    .expect("prepare ICMP pipeline U2C transmit session");
    crate::net::icmp_sequence::install_outbound_request_session(
        upstream_sequences,
        &mut upstream_sequences.cache(),
        upstream_transmit_session,
    )
    .expect("prepare ICMP pipeline C2U transmit session");
    crate::net::icmp_sequence::activate_receive_session(
        upstream_sequences,
        &mut upstream_sequences.cache(),
        upstream_receive_session,
    );
    super::icmp_pipeline_fixture::assert_admitted(
        true,
        &cfg,
        &handles,
        &admission_snapshot,
        &super::icmp_pipeline_fixture::receive_packet(
            handles.listener.parser,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            super::icmp_pipeline_fixture::packet(
                handles.listener.listen_local_filter.id(),
                client_endpoint.id(),
                1,
                session,
                false,
                b"fixture-c2u",
            ),
        ),
        client_address,
    );
    super::icmp_pipeline_fixture::assert_admitted(
        false,
        &cfg,
        &handles,
        &admission_snapshot,
        &super::icmp_pipeline_fixture::receive_packet(
            handles.upstream.parser,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            super::icmp_pipeline_fixture::packet(
                handles.upstream.upstream_local_filter.id(),
                handles.upstream.upstream_remote_filter.id(),
                2,
                upstream_receive_session,
                true,
                b"fixture-u2c",
            ),
        ),
        upstream_address,
    );
    IcmpPipelineState {
        handles,
        cfg,
        session,
        upstream_receive_session,
        client_endpoint,
    }
}

fn prove_icmp_complete_pipeline_overlap(paused_c2u: bool, stage: PipelineStage) {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ICMP pipeline client");
    client
        .set_read_timeout(Some(PIPELINE_TIMEOUT))
        .expect("set ICMP pipeline client timeout");
    let client_address = client.local_addr().expect("ICMP pipeline client address");
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ICMP pipeline upstream");
    upstream
        .set_read_timeout(Some(PIPELINE_TIMEOUT))
        .expect("set ICMP pipeline upstream timeout");
    let upstream_address = upstream
        .local_addr()
        .expect("ICMP pipeline upstream address");
    let manager = Arc::new(unconnected_pipeline_manager(
        SupportedProtocol::ICMP,
        upstream_address,
    ));
    let managers = [Arc::clone(&manager)];
    let flow_state = FlowRuntimeState::new();
    let client_sequences = SharedIcmpSequenceState::new();
    let upstream_sequences = SharedIcmpSequenceState::new();
    let IcmpPipelineState {
        handles,
        cfg,
        session,
        upstream_receive_session,
        client_endpoint,
    } = configure_icmp_pipeline(
        &manager,
        &flow_state,
        &client_sequences,
        &upstream_sequences,
        client_address,
        upstream_address,
    );
    let listener_address = handles.listener.listen_local_kernel_addr;
    let upstream_local_address = handles.upstream.upstream_local_kernel_addr;
    let stats = crate::stats::Stats::new(2, false).expect("disabled ICMP pipeline stats");
    let mut c2u_stats = stats.try_recorder(0).expect("ICMP pipeline C2U recorder");
    let mut u2c_stats = stats.try_recorder(1).expect("ICMP pipeline U2C recorder");
    let shutdown = ShutdownController::new(2).expect("ICMP pipeline shutdown controller");
    let mut pause =
        TestPipelinePause::arm(paused_c2u, stage).expect("arm complete ICMP pipeline barrier");
    let token = pause.token();

    std::thread::scope(|scope| {
        let cfg_ref = &cfg;
        let manager_ref = &manager;
        let managers_ref = &managers;
        let flow_state_ref = &flow_state;
        let client_sequences_ref = &client_sequences;
        let upstream_sequences_ref = &upstream_sequences;
        let shutdown_ref = &shutdown;
        let c2u = scope.spawn(move || {
            let token_guard = paused_c2u.then(|| TestPipelineThreadToken::install(token));
            run_client_to_upstream_thread(ClientWorkerContext {
                t_start: Instant::now(),
                cfg: cfg_ref,
                sock_mgr: manager_ref,
                all_sock_mgrs: managers_ref,
                worker_id: 0,
                flow_lane: FlowReaderLane::new(0),
                flow_state: flow_state_ref,
                stats: &mut c2u_stats,
                client_side_state: client_sequences_ref,
                upstream_side_state: upstream_sequences_ref,
                sync_pacer: None,
                flow_claims: None,
                worker_pair_id: 0,
                exit_code_set: shutdown_ref,
            });
            drop(token_guard);
        });
        let u2c = scope.spawn(move || {
            let token_guard = (!paused_c2u).then(|| TestPipelineThreadToken::install(token));
            run_upstream_to_client_thread(UpstreamWorkerContext {
                t_start: Instant::now(),
                cfg: cfg_ref,
                sock_mgr: manager_ref,
                all_sock_mgrs: managers_ref,
                worker_id: 1,
                flow_lane: FlowReaderLane::new(1),
                flow_state: flow_state_ref,
                stats: &mut u2c_stats,
                client_side_state: client_sequences_ref,
                upstream_side_state: upstream_sequences_ref,
                exit_code_set: shutdown_ref,
            });
            drop(token_guard);
        });

        let paused_payload = if paused_c2u {
            b"paused-icmp-c2u".as_slice()
        } else {
            b"paused-icmp-u2c".as_slice()
        };
        let paused_packet = if paused_c2u {
            super::icmp_pipeline_fixture::receive_packet(
                handles.listener.parser,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
                super::icmp_pipeline_fixture::packet(
                    handles.listener.listen_local_filter.id(),
                    client_endpoint.id(),
                    10,
                    session,
                    false,
                    paused_payload,
                ),
            )
        } else {
            super::icmp_pipeline_fixture::receive_packet(
                handles.upstream.parser,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
                super::icmp_pipeline_fixture::packet(
                    handles.upstream.upstream_local_filter.id(),
                    handles.upstream.upstream_remote_filter.id(),
                    11,
                    upstream_receive_session,
                    true,
                    paused_payload,
                ),
            )
        };
        let (paused_source, paused_destination) = if paused_c2u {
            (&client, listener_address)
        } else {
            (&upstream, upstream_local_address)
        };
        paused_source
            .send_to(&paused_packet, paused_destination)
            .expect("send paused ICMP pipeline packet");
        if !pause.wait_until_arrived(PIPELINE_TIMEOUT) {
            pause.release();
            shutdown_ref.request_graceful(0);
            c2u.join().expect("join stalled ICMP pipeline C2U worker");
            u2c.join().expect("join stalled ICMP pipeline U2C worker");
            panic!("paused ICMP direction did not reach {stage:?}");
        }

        let progressed = if paused_c2u {
            let packet = super::icmp_pipeline_fixture::receive_packet(
                handles.upstream.parser,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
                super::icmp_pipeline_fixture::packet(
                    handles.upstream.upstream_local_filter.id(),
                    handles.upstream.upstream_remote_filter.id(),
                    12,
                    upstream_receive_session,
                    true,
                    b"progress-icmp-u2c",
                ),
            );
            upstream
                .send_to(&packet, upstream_local_address)
                .expect("send progressing ICMP U2C packet");
            receive_icmp_payload(&client, b"progress-icmp-u2c")
        } else {
            let packet = super::icmp_pipeline_fixture::receive_packet(
                handles.listener.parser,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
                super::icmp_pipeline_fixture::packet(
                    handles.listener.listen_local_filter.id(),
                    client_endpoint.id(),
                    13,
                    session,
                    false,
                    b"progress-icmp-c2u",
                ),
            );
            client
                .send_to(&packet, listener_address)
                .expect("send progressing ICMP C2U packet");
            receive_icmp_payload(&upstream, b"progress-icmp-c2u")
        };

        pause.release();
        let paused_completed = if paused_c2u {
            receive_icmp_payload(&upstream, paused_payload)
        } else {
            receive_icmp_payload(&client, paused_payload)
        };
        shutdown_ref.request_graceful(0);
        c2u.join().expect("join complete ICMP pipeline C2U worker");
        u2c.join().expect("join complete ICMP pipeline U2C worker");
        assert!(
            matches!(progressed, Ok(true)),
            "opposite ICMP direction did not forward at {stage:?}: {progressed:?}; fatal={:?}",
            shutdown_ref.primary_fatal_outcome()
        );
        assert!(
            matches!(paused_completed, Ok(true)),
            "paused ICMP direction did not complete at {stage:?}: {paused_completed:?}; fatal={:?}",
            shutdown_ref.primary_fatal_outcome()
        );
    });
}

#[test]
fn udp_and_active_icmp_directions_overlap_through_real_stable_send_authorities() {
    let _suite = TestPipelineSuiteGuard::acquire().expect("serialize singleton pipeline hook");
    prove_bidirectional_send_overlap(SupportedProtocol::UDP);
    prove_bidirectional_send_overlap(SupportedProtocol::ICMP);
}

#[test]
fn udp_directions_overlap_through_complete_production_receive_to_send_pipeline() {
    let _suite = TestPipelineSuiteGuard::acquire().expect("serialize singleton pipeline hook");
    for direction in [true, false] {
        for stage in COMPLETE_PIPELINE_STAGES {
            prove_udp_complete_pipeline_overlap(direction, stage);
        }
    }
}

#[test]
fn icmp_directions_overlap_through_complete_production_receive_to_send_pipeline() {
    let _suite = TestPipelineSuiteGuard::acquire().expect("serialize singleton pipeline hook");
    for direction in [true, false] {
        for stage in COMPLETE_PIPELINE_STAGES {
            prove_icmp_complete_pipeline_overlap(direction, stage);
        }
    }
}
