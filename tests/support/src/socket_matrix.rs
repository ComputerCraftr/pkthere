use crate::matrix::MatrixCase;
use pkthere_socket_policy::{
    IcmpPolicyIntent, ProtocolPolicyIntent, SocketRole, TimeoutAction,
    listener_worker_socket_policy, resolve_listener_socket_policy_with_protocol_intent,
    resolve_socket_policy_with_protocol_intent,
};
use pkthere_wire::SupportedProtocol;
use socket2::Type;

fn worker_str<'a>(worker: &'a serde_json::Value, field: &str) -> &'a str {
    worker[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing {field}"))
}

pub fn assert_socket_matrix_state(
    worker: &serde_json::Value,
    case: MatrixCase,
    timeout_action: TimeoutAction,
    case_desc: &str,
) {
    assert_identity_fields(worker, case_desc);
    let listener_policy = resolve_listener_socket_policy_with_protocol_intent(
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        timeout_action,
        case.client_connection.debug_force_unconnected(),
        case.family,
        listener_worker_socket_policy(1, false),
    );
    let listener_lifecycle = listener_policy
        .listener_lifecycle
        .expect("listener policy must resolve a lifecycle");
    let upstream_policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        match case.proto {
            SupportedProtocol::UDP => ProtocolPolicyIntent::Udp,
            SupportedProtocol::ICMP => ProtocolPolicyIntent::Icmp(IcmpPolicyIntent {
                allow_debug_kernel_echo_self_handshake: true,
                ..IcmpPolicyIntent::default()
            }),
        },
        Type::DGRAM,
        timeout_action,
        case.upstream_connection.debug_force_unconnected(),
        case.family,
    );
    let listener_expected = listener_lifecycle.connects_after_lock();
    let upstream_expected = upstream_policy.reuse.starts_connected();
    assert_eq!(
        worker_str(worker, "listener_lifecycle"),
        listener_lifecycle.wire_name(),
        "{case_desc}: emitted listener lifecycle differs from independently resolved policy"
    );
    assert_eq!(
        worker_str(worker, "upstream_peer_mode"),
        upstream_policy.reuse.startup_peer_mode.wire_name(),
        "{case_desc}: emitted upstream peer mode differs from independently resolved policy"
    );
    assert_eq!(
        worker["listener_connected"]
            .as_bool()
            .expect("missing listener_connected"),
        listener_expected,
        "{case_desc}: listener_connected mismatch"
    );
    assert_eq!(
        worker["upstream_connected"]
            .as_bool()
            .expect("missing upstream_connected"),
        upstream_expected,
        "{case_desc}: upstream_connected mismatch"
    );
}

fn assert_identity_fields(worker: &serde_json::Value, case_desc: &str) {
    for field in [
        "listener_flow_outbound",
        "listener_local_filter",
        "upstream_remote_filter",
        "upstream_local_filter",
    ] {
        assert!(
            worker[field].as_str().is_some(),
            "{case_desc}: missing stats identity field {field}"
        );
    }
    for field in [
        "listen_local_kernel_addr",
        "upstream_local_kernel_addr",
        "listen_local_filter_canonical",
        "upstream_remote_filter_canonical",
        "upstream_local_filter_canonical",
        "listen_local_kernel_canonical",
        "upstream_local_kernel_canonical",
    ] {
        assert!(
            worker.get(field).is_none(),
            "{case_desc}: misleading stats identity field {field} should not be emitted"
        );
    }
}
