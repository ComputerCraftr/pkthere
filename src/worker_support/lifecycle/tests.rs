use super::run_watchdog_thread;
use crate::cli::{
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeConfig,
    RuntimeOptions, SupportedProtocol, TimeoutAction, WorkerFlowMode,
};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::flow_state::FlowRuntimeState;
use crate::net::managed_socket::test_support::{FakeBackend, unconfigured_fake_socket};
use crate::net::sock_mgr::{ClientFlowUpdate, SocketManager, SocketManagerInit};
use crate::runtime_support::ShutdownController;
use pkthere_socket_policy::{
    ProtocolPolicyIntent, SocketLifecycleContext, SocketPathContext, SocketPolicyContext,
    listener_worker_socket_policy, resolve_listener_socket_policy_for_creation_path_with_lifecycle,
};
use socket2::{Domain, Type};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn exit_timeout_config(listen: SocketAddr, upstream: SocketAddr) -> RuntimeConfig {
    RuntimeConfig {
        listen: LogicalEndpoint::from_socket_addr(listen),
        listener_source_id_request: IcmpReplyIdRequest::Default,
        listener_reply_id_request: IcmpReplyIdRequest::Default,
        listen_proto: SupportedProtocol::UDP,
        listen_mode: ListenMode::Dynamic,
        listen_str: listen.to_string(),
        upstream: LogicalEndpoint::from_socket_addr(upstream),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: SupportedProtocol::UDP,
        upstream_str: upstream.to_string(),
        options: RuntimeOptions {
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            timeout_secs: 0,
            icmp_handshake_timeout_secs: 1,
            on_timeout: TimeoutAction::Exit,
            stats_interval_mins: 0,
            max_payload: 1500,
            icmp_sync_pps: 0,
            icmp_session_pool_size: crate::cli::DEFAULT_ICMP_SESSION_POOL_SIZE,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::None,
            debug_reresolve_address_file: None,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        },
    }
}

#[test]
fn process_exit_timeout_performs_no_disconnect_replacement_or_flow_clear() {
    let backend = Arc::new(FakeBackend::default());
    let client_sock = unconfigured_fake_socket(Arc::clone(&backend));
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let upstream_peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind upstream test peer");
    let upstream = upstream_peer.local_addr().expect("read upstream test peer");
    let worker_policy = listener_worker_socket_policy(1, false);
    let listen_policy = resolve_listener_socket_policy_for_creation_path_with_lifecycle(
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Exit,
        false,
        SocketPolicyContext {
            path: SocketPathContext {
                family: Domain::IPV4,
                creation_path: pkthere_socket_policy::SocketCreationPath::Datagram,
            },
            lifecycle: SocketLifecycleContext::for_requested_bind(
                listen,
                worker_policy.reuse_address,
                worker_policy.reuse_port,
            ),
        },
        worker_policy,
    );
    let manager = Arc::new(
        SocketManager::new(SocketManagerInit {
            socket_slot: 0,
            worker_io_lanes: 2,
            client_sock,
            listen_local_filter: LogicalEndpoint::from_socket_addr(listen),
            listen_local_kernel_addr: listen,
            listen_sock_type: Type::DGRAM,
            listen_target: listen.to_string(),
            listen_proto: SupportedProtocol::UDP,
            listen_policy,
            listen_worker_socket_policy: worker_policy,
            listen_debug_unconnected: false,
            upstream_remote_filter: LogicalEndpoint::from_socket_addr(upstream),
            upstream_target: upstream.to_string(),
            upstream_source_id_request: IcmpReplyIdRequest::Default,
            upstream_reply_id_request: IcmpReplyIdRequest::Default,
            upstream_proto: SupportedProtocol::UDP,
            upstream_debug_unconnected: false,
            upstream_icmp_kernel_echo_self_handshake: false,
            upstream_worker_socket_policy: Default::default(),
            shared_upstream_identity: None,
            force_raw_icmp_wildcard_upstream: false,
            timeout_act: TimeoutAction::Exit,
            debug_handles: false,
        })
        .expect("create exit-policy manager"),
    );
    let flow_state = Arc::new(FlowRuntimeState::new());
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 41_001));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));
    let prepared = SocketManager::prepare_client_flow_group(
        &[manager.as_ref()],
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            admitting_listener_slot: 0,
            client,
        },
    )
    .expect("prepare exit-policy flow");
    let mut transaction = flow_state.reserve_client_flow();
    SocketManager::begin_client_flow_group_transition(prepared, &mut transaction)
        .expect("begin exit-policy flow")
        .publish(None)
        .expect("establish exit-policy flow");
    drop(transaction);
    let t_start = Instant::now();
    flow_state.record_activity(t_start, t_start + Duration::from_millis(1));
    let before = manager.snapshot_state();
    let before_version = before.version;
    let before_epoch = manager.test_handle_snapshot().client_sock.topology_epoch();
    let calls_before = backend.state.lock().expect("fake backend").calls.clone();
    let shutdown = ShutdownController::new(1).expect("create shutdown controller");
    let cfg = exit_timeout_config(listen, upstream);

    run_watchdog_thread(
        t_start,
        &cfg,
        &[Arc::clone(&manager)],
        &[Arc::clone(&flow_state)],
        &shutdown,
        None,
    );

    assert_eq!(shutdown.exit_status(), Some(0));
    assert_eq!(
        backend.state.lock().expect("fake backend").calls,
        calls_before,
        "ProcessExit must not invoke the disconnect backend"
    );
    assert_eq!(manager.snapshot_state().version, before_version);
    assert_eq!(
        manager.test_handle_snapshot().client_sock.topology_epoch(),
        before_epoch
    );
    assert_eq!(
        manager.snapshot_state().listen_evidence_key,
        before.listen_evidence_key,
        "ProcessExit must not replace the listener descriptor"
    );
    assert!(flow_state.is_locked());
    assert_eq!(
        manager
            .try_snapshot_state()
            .expect("manager flow")
            .locked_flow,
        Some(flow)
    );
}
