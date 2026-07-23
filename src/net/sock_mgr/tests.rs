use super::state::{
    ReresolveAction, SocketUpdateKind, decide_listener_reresolve, decide_upstream_reresolve,
};
use super::{SocketManager, SocketManagerInit};
use crate::cli::{IcmpReplyIdRequest, ReresolveMode, SupportedProtocol, TimeoutAction::Drop};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::net::managed_socket::AssociationState;
use crate::net::socket::make_socket;
use pkthere_socket_policy::{
    IcmpPolicyIntent, SocketRole, listener_worker_socket_policy,
    resolve_socket_policy_with_icmp_intent,
};
use socket2::{Domain, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

fn make_mgr() -> SocketManager {
    make_mgr_with_slot(0)
}

fn make_mgr_with_slot(socket_slot: u32) -> SocketManager {
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (client_sock, actual_listen, listen_local_kernel_addr, listen_sock_type, listen_policy) =
        make_socket(
            listen_addr,
            SupportedProtocol::UDP,
            1000,
            listener_worker_socket_policy(1, false),
            Drop,
            false,
            false,
        )
        .expect("create client sock");

    let upstream_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind upstream udp");
    let upstream_addr = upstream_sock.local_addr().expect("upstream udp addr");

    SocketManager::new(SocketManagerInit {
        socket_slot,
        client_sock,
        listen_local_filter: actual_listen,
        listen_local_kernel_addr,
        listen_sock_type,
        listen_target: actual_listen.to_socket_addr().to_string(),
        listen_proto: SupportedProtocol::UDP,
        listen_policy,
        listen_worker_socket_policy: listener_worker_socket_policy(1, false),
        listen_debug_unconnected: false,
        upstream_remote_filter: LogicalEndpoint::from_socket_addr(upstream_addr),
        upstream_target: upstream_addr.to_string(),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: SupportedProtocol::UDP,
        upstream_debug_unconnected: false,
        upstream_icmp_kernel_echo_self_handshake: false,
        force_raw_icmp_wildcard_upstream: false,
        timeout_act: Drop,
        debug_handles: false,
    })
    .expect("create socket manager")
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
fn reconnect_in_place_preserves_socket_slot_and_generation() {
    let mgr = make_mgr_with_slot(4);
    let before = mgr.snapshot_state().upstream_evidence_key;
    let replacement = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind replacement upstream");
    let replacement_addr = replacement.local_addr().expect("replacement upstream addr");

    let handles = mgr
        .reresolve_with_addresses(true, false, "test reconnect", None, Some(replacement_addr))
        .expect("UDP reconnect in place")
        .handles;

    assert_eq!(handles.upstream.evidence_key, before);
    assert_eq!(handles.upstream.evidence_key.socket_slot, 4);
    assert_eq!(handles.upstream.evidence_key.generation, 1);
}

#[test]
fn refresh_notices_raced_updates() {
    let mgr = make_mgr();
    let mut cached = mgr.refresh_handles();
    let v0 = cached.version;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);
    mgr.establish_client_flow(
        ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(addr)),
        SocketLegFlow::empty(),
        true,
        addr,
        v0,
    )
    .expect("establish client flow");
    mgr.clear_client_lock(v0 + 1).expect("clear client flow");

    assert_ne!(cached.version, mgr.get_version());
    cached = mgr.refresh_handles();
    assert_eq!(cached.version, mgr.get_version());
    assert_eq!(cached.listener.flow, None);
    assert!(!cached.listener_connected());
}

#[test]
fn cached_handles_keep_immutable_metadata_and_share_socket_association() {
    let mgr = make_mgr();
    let old = mgr.refresh_handles();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);

    mgr.establish_client_flow(
        ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
        SocketLegFlow::empty(),
        true,
        client,
        old.version,
    )
    .expect("establish client flow");
    let fresh = mgr.refresh_handles();

    assert!(!Arc::ptr_eq(&old.listener, &fresh.listener));
    assert_eq!(old.listener.flow, None);
    assert!(old.listener_connected());
    assert_eq!(
        fresh.listener.flow,
        Some(ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(
            client
        )))
    );
    assert!(fresh.listener_connected());
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
    let mgr = make_mgr();
    let before = mgr.get_version();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33334);
    let key = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));

    let published = mgr
        .establish_client_flow(key, SocketLegFlow::empty(), false, client, before)
        .expect("establish an explicitly unconnected client flow");
    let handles = mgr.refresh_handles();

    assert_eq!(published, before + 1);
    assert_eq!(handles.listener.flow, Some(key));
    assert!(!handles.listener_connected());
}

#[test]
fn rejected_client_transaction_preserves_existing_flow_and_version() {
    let mgr = make_mgr();
    let first_client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33335);
    let first_key = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(first_client));
    let first_version = mgr
        .establish_client_flow(
            first_key,
            SocketLegFlow::empty(),
            true,
            first_client,
            mgr.get_version(),
        )
        .expect("establish connected client flow");
    let rejected_client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33336);
    let rejected_key = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(rejected_client));

    assert!(
        mgr.establish_client_flow(
            rejected_key,
            SocketLegFlow::empty(),
            false,
            rejected_client,
            first_version,
        )
        .is_err()
    );
    let handles = mgr.refresh_handles();
    assert_eq!(handles.version, first_version);
    assert_eq!(handles.listener.flow, Some(first_key));
    assert!(handles.listener_connected());
}

#[test]
fn replacement_resets_association_epoch_and_advances_socket_generation() {
    let mgr = make_mgr_with_slot(5);
    let before = mgr.snapshot_state().upstream_evidence_key;
    let replacement = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .expect("bind IPv6 replacement upstream");
    let replacement_addr = replacement.local_addr().expect("IPv6 replacement address");

    let result = mgr
        .reresolve_with_addresses(
            true,
            false,
            "test cross-family replacement",
            None,
            Some(replacement_addr),
        )
        .expect("replace upstream socket across families");

    assert_eq!(
        result.upstream_update,
        SocketUpdateKind::ReplacedCrossFamily
    );
    assert_eq!(result.handles.upstream.evidence_key.generation, 2);
    assert_eq!(result.handles.upstream.evidence_key.socket_slot, 5);
    assert_ne!(result.handles.upstream.evidence_key, before);
    assert!(matches!(
        result.handles.upstream_sock.association(),
        AssociationState::Connected { epoch: 1, .. }
    ));
}

#[test]
fn snapshot_preserves_role_specific_identity_names() {
    let mgr = make_mgr();
    let snapshot = mgr.snapshot_state();

    assert_eq!(snapshot.listener_flow, SocketLegFlow::empty());
    assert_eq!(snapshot.listen_local_filter, mgr.get_listen_addr());
    assert_eq!(snapshot.upstream_remote_filter, mgr.get_upstream_dest().0);
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
    let v0 = mgr.get_version();
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

    mgr.set_upstream_peer_ids(7777, 9999, v0);
    let handles = mgr.refresh_handles();
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
fn upstream_same_family_connected_prefers_reconnect_when_policy_allows() {
    let prev = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444),
        5555,
    );
    let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 9999);
    let policy = resolve_socket_policy_with_icmp_intent(
        SocketRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        Drop,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
    );
    let (fresh, action) = decide_upstream_reresolve(prev, resolved, true, policy);

    assert_eq!(fresh.id(), 5555);
    assert_eq!(fresh.ip(), resolved.ip());
    assert_eq!(action, ReresolveAction::ReconnectInPlace);
}

#[test]
fn upstream_raw_same_family_change_falls_back_to_replace() {
    let prev = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444),
        5555,
    );
    let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 9999);
    let policy = resolve_socket_policy_with_icmp_intent(
        SocketRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        Drop,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
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
    let policy = resolve_socket_policy_with_icmp_intent(
        SocketRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        Drop,
        true,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
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
            "test",
        )
        .is_ok(),
        "none must skip both invalid targets"
    );
    assert!(
        mgr.reresolve(
            ReresolveMode::Upstream.allow_upstream(),
            ReresolveMode::Upstream.allow_listen(),
            "test",
        )
        .is_err(),
        "upstream mode must attempt only the invalid upstream target"
    );
    assert!(
        mgr.reresolve(
            ReresolveMode::Listen.allow_upstream(),
            ReresolveMode::Listen.allow_listen(),
            "test",
        )
        .is_err(),
        "listen mode must attempt only the invalid listen target"
    );
    assert!(
        mgr.reresolve(
            ReresolveMode::Both.allow_upstream(),
            ReresolveMode::Both.allow_listen(),
            "test",
        )
        .is_err(),
        "both mode must attempt at least one invalid target"
    );
}
