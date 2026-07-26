use super::state::{
    ReresolveAction, SocketUpdateKind, decide_listener_reresolve, decide_upstream_reresolve,
};
use super::{ClientFlowUpdate, ManagerError, SocketManager, SocketManagerInit, StateVersion};
use crate::cli::{IcmpReplyIdRequest, ReresolveMode, SupportedProtocol, TimeoutAction::Drop};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::flow_state::FlowRuntimeState;
use crate::net::managed_socket::AssociationState;
use crate::net::sock_mgr::receiver_slot::ReceiverRole;
use crate::net::socket::make_socket;
use pkthere_socket_policy::{
    IcmpPolicyIntent, ListenerWorkerSocketPolicy, ProtocolPolicyIntent, SocketRole,
    listener_worker_socket_policy, resolve_socket_policy_with_protocol_intent,
};
use socket2::{Domain, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

macro_rules! establish_prepared_client_flow {
    ($prepared:expr, $transaction:expr) => {{
        SocketManager::begin_client_flow_group_transition($prepared, $transaction)
            .and_then(|transition| transition.publish(None))
    }};
}
pub(super) use establish_prepared_client_flow;

#[cfg(not(miri))]
impl SocketManager {
    pub(in crate::net::sock_mgr) fn with_initial_version_for_test(
        mut self,
        version: StateVersion,
    ) -> Self {
        self.version = super::version::VersionClock::with_initial(version);
        self
    }
}

pub(super) fn set_test_upstream_peer_ids(
    manager: &SocketManager,
    observed_topology_epoch: u64,
    source_id: u16,
    reply_id: u16,
) -> Result<super::PublishedUpdate, ManagerError> {
    let mut updates = SocketManager::set_upstream_peer_ids_group_at_topology(
        &[manager],
        manager.socket_slot(),
        observed_topology_epoch,
        source_id,
        reply_id,
    )?;
    updates
        .pop()
        .ok_or_else(|| ManagerError::TransactionFailed {
            operation: "test upstream peer-ID publication",
            cause: "production group transaction returned no update".into(),
            journal: Vec::new(),
        })
}

pub(super) fn make_mgr() -> SocketManager {
    make_mgr_with_slot(0)
}

pub(super) fn make_mgr_with_slot(socket_slot: u32) -> SocketManager {
    make_mgr_with_slot_and_worker_policy(socket_slot, listener_worker_socket_policy(2, false))
}

pub(super) fn make_mgr_with_slot_and_worker_policy(
    socket_slot: u32,
    worker_policy: ListenerWorkerSocketPolicy,
) -> SocketManager {
    make_mgr_with_slot_worker_policy_and_debug(socket_slot, worker_policy, false)
}

pub(super) fn make_mgr_with_slot_worker_policy_and_debug(
    socket_slot: u32,
    worker_policy: ListenerWorkerSocketPolicy,
    debug_unconnected: bool,
) -> SocketManager {
    make_mgr_with_slot_worker_policy_debug_and_source_request(
        socket_slot,
        worker_policy,
        debug_unconnected,
        IcmpReplyIdRequest::Default,
    )
}

pub(super) fn make_mgr_with_slot_worker_policy_debug_and_source_request(
    socket_slot: u32,
    worker_policy: ListenerWorkerSocketPolicy,
    debug_unconnected: bool,
    upstream_source_id_request: IcmpReplyIdRequest,
) -> SocketManager {
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (client_sock, actual_listen, listen_local_kernel_addr, listen_sock_type, listen_policy) =
        make_socket(
            listen_addr,
            SupportedProtocol::UDP,
            worker_policy,
            Drop,
            debug_unconnected,
            false,
        )
        .expect("create client sock");

    let upstream_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind upstream udp");
    let upstream_addr = upstream_sock.local_addr().expect("upstream udp addr");

    SocketManager::new(SocketManagerInit {
        socket_slot,
        worker_io_lanes: 2,
        client_sock,
        listen_local_filter: actual_listen,
        listen_local_kernel_addr,
        listen_sock_type,
        listen_target: listen_addr.to_string(),
        listen_proto: SupportedProtocol::UDP,
        listen_policy,
        listen_worker_socket_policy: worker_policy,
        listen_debug_unconnected: debug_unconnected,
        upstream_remote_filter: LogicalEndpoint::from_socket_addr(upstream_addr),
        upstream_target: upstream_addr.to_string(),
        upstream_source_id_request,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: SupportedProtocol::UDP,
        upstream_debug_unconnected: false,
        upstream_icmp_kernel_echo_self_handshake: false,
        upstream_worker_socket_policy: Default::default(),
        shared_upstream_identity: None,
        force_raw_icmp_wildcard_upstream: false,
        timeout_act: Drop,
        debug_handles: false,
    })
    .expect("create socket manager")
}

pub(super) fn listener_policy_connects_after_lock(manager: &SocketManager) -> bool {
    manager
        .test_handle_snapshot()
        .listener
        .policy
        .listener_lifecycle
        .is_some_and(pkthere_socket_policy::ListenerLockLifecycle::connects_after_lock)
}

pub(super) fn establish_test_client_flow(
    manager: &SocketManager,
    flow_state: &FlowRuntimeState,
    flow: ClientFlowKey,
    listener_flow: SocketLegFlow,
    client: SocketAddr,
) -> Result<StateVersion, ManagerError> {
    let prepared = SocketManager::prepare_client_flow_group(
        &[manager],
        ClientFlowUpdate {
            flow,
            listener_flow,
            admitting_listener_slot: manager.socket_slot(),
            client,
        },
    )?;
    let mut transaction = flow_state.reserve_client_flow();
    let mut updates =
        SocketManager::begin_client_flow_group_transition(prepared, &mut transaction)?
            .publish(None)?;
    assert_eq!(updates.len(), 1);
    Ok(updates
        .pop()
        .expect("single manager update")
        .handles
        .version)
}

pub(super) fn clear_test_client_flow(
    manager: &SocketManager,
    flow_state: &FlowRuntimeState,
) -> Result<StateVersion, ManagerError> {
    let mut transaction = flow_state.reserve_client_flow();
    let mut updates = SocketManager::clear_client_flow_group(&[manager], &mut transaction)?.updates;
    assert_eq!(updates.len(), 1);
    Ok(updates.pop().expect("single manager clear").handles.version)
}

#[test]
fn same_family_worker_pairs_have_distinct_evidence_slots() {
    let first = make_mgr_with_slot(0).snapshot_state();
    let second = make_mgr_with_slot(1).snapshot_state();

    for (first_key, second_key) in [
        (first.listen_evidence_key, second.listen_evidence_key),
        (first.upstream_evidence_key, second.upstream_evidence_key),
    ] {
        assert_eq!(first_key.process_id, second_key.process_id);
        assert_eq!(first_key.role, second_key.role);
        assert_eq!(first_key.domain, second_key.domain);
        assert_eq!(first_key.generation, second_key.generation);
        assert_eq!(first_key.socket_slot, 0);
        assert_eq!(second_key.socket_slot, 1);
        assert_ne!(first_key, second_key);
    }
}

#[test]
fn replacement_preserves_socket_slot_and_advances_generation() {
    let mgr = make_mgr_with_slot(4);
    let before_state = mgr.snapshot_state();
    let before = before_state.upstream_evidence_key;
    let original_target_guard =
        UdpSocket::bind(before_state.upstream_remote_filter.to_socket_addr())
            .expect("retain the original upstream target address during replacement");
    let replacement = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind replacement upstream");
    let replacement_addr = replacement.local_addr().expect("replacement upstream addr");

    let handles = mgr
        .reresolve_with_addresses(true, false, None, Some(replacement_addr))
        .expect("UDP replacement")
        .handles;

    assert_eq!(handles.upstream.evidence_key.socket_slot, 4);
    assert_eq!(
        handles.upstream.evidence_key.generation,
        before.generation + 1
    );
    drop(original_target_guard);
}

#[test]
fn reconnect_preserves_required_udp_source_port_or_replaces_the_socket() {
    let reservation = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("reserve explicit UDP source port");
    let requested_port = reservation
        .local_addr()
        .expect("reserved UDP source address")
        .port();
    drop(reservation);

    let mgr = make_mgr_with_slot_worker_policy_debug_and_source_request(
        7,
        listener_worker_socket_policy(2, false),
        false,
        IcmpReplyIdRequest::Fixed(requested_port),
    );
    let before = mgr.test_handle_snapshot();
    assert_eq!(
        before.upstream.upstream_local_kernel_addr.port(),
        requested_port
    );

    let replacement_peer = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind replacement peer");
    let replacement_peer_addr = replacement_peer
        .local_addr()
        .expect("replacement peer address");
    let summary = mgr
        .reresolve_with_addresses(true, false, None, Some(replacement_peer_addr))
        .expect("reconnect or recover with replacement");

    assert_eq!(
        summary.handles.upstream.upstream_local_kernel_addr.port(),
        requested_port,
        "a required local UDP source port must survive the topology update"
    );
    assert_eq!(summary.upstream_update, SocketUpdateKind::Replaced);
    assert_eq!(
        summary.handles.upstream.evidence_key.generation,
        before.upstream.evidence_key.generation + 1
    );
}

#[test]
fn handle_snapshot_observes_raced_updates() {
    let mgr = make_mgr();
    let flow_state = FlowRuntimeState::new();
    let mut cached = mgr.test_handle_snapshot();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);
    establish_test_client_flow(
        &mgr,
        &flow_state,
        ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(addr)),
        SocketLegFlow::empty(),
        addr,
    )
    .expect("establish client flow");
    clear_test_client_flow(&mgr, &flow_state).expect("clear client flow");

    assert_ne!(cached.version, mgr.test_handle_snapshot().version);
    cached = mgr.test_handle_snapshot();
    assert_eq!(cached.version, mgr.test_handle_snapshot().version);
    assert_eq!(cached.listener.flow, None);
    assert!(!cached.listener_connected());
}

#[test]
fn cached_handles_keep_immutable_metadata_and_share_socket_association() {
    let mgr = make_mgr();
    let connects_after_lock = listener_policy_connects_after_lock(&mgr);
    let flow_state = FlowRuntimeState::new();
    let old = mgr.test_handle_snapshot();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);

    establish_test_client_flow(
        &mgr,
        &flow_state,
        ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
        SocketLegFlow::empty(),
        client,
    )
    .expect("establish client flow");
    let fresh = mgr.test_handle_snapshot();

    assert!(!Arc::ptr_eq(&old.listener, &fresh.listener));
    assert_eq!(old.listener.flow, None);
    assert_eq!(old.listener_connected(), connects_after_lock);
    assert_eq!(
        fresh.listener.flow,
        Some(ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(
            client
        )))
    );
    assert_eq!(fresh.listener_connected(), connects_after_lock);
    assert_eq!(old.listener.evidence_key, fresh.listener.evidence_key);
}

#[test]
fn listener_reresolve_uses_logical_endpoint_refresh_rules() {
    let prev = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777),
        8888,
    );
    let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 1234);
    let (fresh, action) = decide_listener_reresolve(prev, resolved);

    assert_eq!(action, ReresolveAction::ReplaceSocket);
    assert_eq!(fresh.id(), 8888);
    assert_eq!(fresh.ip(), resolved.ip());
}

#[test]
fn unconnected_client_flow_publishes_metadata_without_socket_association() {
    let mgr = make_mgr_with_slot_worker_policy_and_debug(
        0,
        listener_worker_socket_policy(2, false),
        true,
    );
    let flow_state = FlowRuntimeState::new();
    let before = mgr.test_handle_snapshot().version;
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33334);
    let key = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));

    let published =
        establish_test_client_flow(&mgr, &flow_state, key, SocketLegFlow::empty(), client)
            .expect("establish an explicitly unconnected client flow");
    let handles = mgr.test_handle_snapshot();

    assert_eq!(published.get(), before.get() + 1);
    assert_eq!(handles.listener.flow, Some(key));
    assert!(!handles.listener_connected());
}

#[test]
fn rejected_client_transaction_preserves_existing_flow_and_version() {
    let mgr = make_mgr();
    let connects_after_lock = listener_policy_connects_after_lock(&mgr);
    let flow_state = FlowRuntimeState::new();
    let first_client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33335);
    let first_key = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(first_client));
    let first_version = establish_test_client_flow(
        &mgr,
        &flow_state,
        first_key,
        SocketLegFlow::empty(),
        first_client,
    )
    .expect("establish connected client flow");
    let rejected_client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33336);
    let rejected_key = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(rejected_client));

    assert!(
        establish_test_client_flow(
            &mgr,
            &flow_state,
            rejected_key,
            SocketLegFlow::empty(),
            rejected_client,
        )
        .is_err()
    );
    let handles = mgr.test_handle_snapshot();
    assert_eq!(handles.version, first_version);
    assert_eq!(handles.listener.flow, Some(first_key));
    assert_eq!(handles.listener_connected(), connects_after_lock);
}

#[test]
fn replacement_resets_association_epoch_and_advances_socket_generation() {
    let mgr = make_mgr_with_slot(5);
    let flow_state = FlowRuntimeState::new();
    let receiver = mgr
        .claim_receiver(ReceiverRole::Upstream, 5)
        .expect("claim upstream receiver");
    let old_handles = mgr.test_handle_snapshot();
    let authority = crate::worker_support::ReceiveAuthority::capture(
        &old_handles,
        crate::worker_support::SocketLeg::UpstreamFacing,
        flow_state.flow_epoch(),
        receiver.generation(),
    );
    let before = mgr.snapshot_state().upstream_evidence_key;
    let replacement = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .expect("bind IPv6 replacement upstream");
    let replacement_addr = replacement.local_addr().expect("IPv6 replacement address");

    let result = mgr
        .reresolve_with_addresses(true, false, None, Some(replacement_addr))
        .expect("replace upstream socket across families");

    assert_eq!(
        result.upstream_update,
        SocketUpdateKind::ReplacedCrossFamily
    );
    assert_eq!(result.handles.upstream.evidence_key.generation, 2);
    assert_eq!(result.handles.upstream.evidence_key.socket_slot, 5);
    assert_ne!(result.handles.upstream.evidence_key, before);
    let replacement_association = result.handles.upstream_sock.association();
    assert!(
        matches!(
            replacement_association,
            AssociationState::Connected { epoch: 1, .. }
        ),
        "replacement association was {replacement_association:?}"
    );
    assert!(
        !authority.matches(
            &result.handles,
            crate::worker_support::SocketLeg::UpstreamFacing,
            flow_state.flow_epoch(),
            mgr.receiver_generation(ReceiverRole::Upstream),
        ),
        "upstream replacement must invalidate pre-commit receive authority"
    );
}

#[test]
fn receiver_publication_failure_cannot_publish_replacement_metadata() {
    let mgr = make_mgr_with_slot(6);
    let before = mgr.test_handle_snapshot();
    let claim = mgr
        .claim_receiver(ReceiverRole::Upstream, 11)
        .expect("claim upstream receiver");
    drop(claim);
    let replacement = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .expect("bind IPv6 replacement upstream");
    let replacement_addr = replacement.local_addr().expect("IPv6 replacement address");

    let error = match mgr.reresolve_with_addresses(true, false, None, Some(replacement_addr)) {
        Ok(_) => panic!("exited receiver owner must reject replacement publication"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("exited"),
        "unexpected receiver publication error: {error}"
    );

    let after = mgr.test_handle_snapshot();
    assert_eq!(after.version, before.version);
    assert_eq!(
        after.upstream.evidence_key, before.upstream.evidence_key,
        "receiver publication failure must not install replacement metadata"
    );
    assert!(after.upstream_sock.same_descriptor(&before.upstream_sock));
}

#[test]
fn snapshot_preserves_role_specific_identity_names() {
    let mgr = make_mgr();
    let snapshot = mgr.snapshot_state();

    assert_eq!(snapshot.listener_flow, SocketLegFlow::empty());
    assert_eq!(snapshot.client_proto, SupportedProtocol::UDP);
    assert_eq!(snapshot.upstream_proto, SupportedProtocol::UDP);
    assert_ne!(snapshot.listen_local_filter.id(), 0);
    assert_ne!(snapshot.upstream_remote_filter.id(), 0);
    assert_eq!(
        snapshot.listener_connected,
        snapshot.listen_policy.reuse.starts_connected()
    );
    assert_eq!(
        snapshot.upstream_connected,
        snapshot.upstream_policy.reuse.starts_connected()
    );
}

#[test]
fn upstream_peer_update_applies_source_id_when_reply_id_is_unchanged() {
    let mgr = make_mgr();
    let v0 = mgr.test_handle_snapshot().version;
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    {
        let mut up = mgr.upstream_state.lock().unwrap();
        up.upstream_remote_filter = LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 9999);
        up.upstream_flow = SocketLegFlow::new(
            Some(FlowTuple::new(
                LogicalEndpoint::new(ip, 9999),
                LogicalEndpoint::new(ip, 40001),
            )),
            Some(FlowTuple::new(
                LogicalEndpoint::new(ip, 40000),
                LogicalEndpoint::new(ip, 9999),
            )),
        );
    }

    let update = set_test_upstream_peer_ids(
        &mgr,
        mgr.test_handle_snapshot().upstream_sock.topology_epoch(),
        7777,
        9999,
    )
    .expect("publish upstream peer IDs");
    assert_ne!(update.handles.version, v0);
    let handles = mgr.test_handle_snapshot();
    assert_eq!(handles.upstream.upstream_remote_filter.id(), 9999);
    assert_eq!(
        handles
            .upstream
            .upstream_flow
            .inbound
            .expect("inbound flow")
            .src
            .id(),
        7777
    );
    assert_eq!(
        handles
            .upstream
            .upstream_flow
            .outbound
            .expect("outbound flow")
            .dst
            .id(),
        9999
    );
}

#[test]
fn upstream_peer_id_no_op_returns_one_coherent_snapshot_without_incrementing() {
    let mgr = make_mgr();
    let before = mgr.test_handle_snapshot();
    let source_id = before
        .upstream
        .upstream_flow
        .inbound
        .expect("initial inbound flow")
        .src
        .id();
    let reply_id = before.upstream.upstream_remote_filter.id();

    let update = set_test_upstream_peer_ids(
        &mgr,
        before.upstream_sock.topology_epoch(),
        source_id,
        reply_id,
    )
    .expect("no-op upstream peer IDs");

    assert_eq!(update.handles.version, before.version);
    assert_eq!(
        update.handles.upstream.upstream_remote_filter,
        before.upstream.upstream_remote_filter
    );
}

#[test]
fn upstream_same_family_connected_uses_policy_authorized_replacement() {
    let prev = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444),
        5555,
    );
    let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 9999);
    let policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        Drop,
        false,
        Domain::IPV4,
    );
    let (fresh, action) = decide_upstream_reresolve(prev, resolved, true, policy);

    assert_eq!(fresh.id(), 5555);
    assert_eq!(fresh.ip(), resolved.ip());
    assert_eq!(action, ReresolveAction::ReplaceSocket);
}

#[test]
fn upstream_raw_same_family_change_falls_back_to_replace() {
    let prev = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444),
        5555,
    );
    let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 9999);
    let policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        Type::RAW,
        Drop,
        false,
        Domain::IPV4,
    );
    let (_, action) = decide_upstream_reresolve(prev, resolved, true, policy);

    assert_eq!(action, ReresolveAction::ReplaceSocket);
}

#[test]
fn upstream_unconnected_same_family_change_only_updates_metadata() {
    let prev = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444),
        5555,
    );
    let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 9999);
    let policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        Drop,
        true,
        Domain::IPV4,
    );
    let (_, action) = decide_upstream_reresolve(prev, resolved, false, policy);

    assert_eq!(action, ReresolveAction::UpdateMetadataOnly);
}

#[test]
fn reresolve_mode_side_gating_is_complete() {
    for (mode, expect_upstream, expect_listen) in [
        (ReresolveMode::None, false, false),
        (ReresolveMode::Upstream, true, false),
        (ReresolveMode::Listen, false, true),
        (ReresolveMode::Both, true, true),
    ] {
        assert_eq!(mode.allow_upstream(), expect_upstream);
        assert_eq!(mode.allow_listen(), expect_listen);
    }
}

#[test]
fn socket_manager_reresolve_respects_side_gating() {
    let mut mgr = make_mgr();
    mgr.listen_target = String::from("invalid-listen-target.invalid:1");
    mgr.upstream_target = String::from("invalid-upstream-target.invalid:1");

    assert!(
        mgr.reresolve(
            ReresolveMode::None.allow_upstream(),
            ReresolveMode::None.allow_listen(),
        )
        .is_ok(),
        "none must skip both invalid targets"
    );
    assert!(
        mgr.reresolve(
            ReresolveMode::Upstream.allow_upstream(),
            ReresolveMode::Upstream.allow_listen(),
        )
        .is_err(),
        "upstream mode must attempt only the invalid upstream target"
    );
    assert!(
        mgr.reresolve(
            ReresolveMode::Listen.allow_upstream(),
            ReresolveMode::Listen.allow_listen(),
        )
        .is_err(),
        "listen mode must attempt only the invalid listen target"
    );
    assert!(
        mgr.reresolve(
            ReresolveMode::Both.allow_upstream(),
            ReresolveMode::Both.allow_listen(),
        )
        .is_err(),
        "both mode must attempt at least one invalid target"
    );
}
