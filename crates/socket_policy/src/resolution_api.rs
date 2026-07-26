use super::{
    DisconnectRealityKey, ListenerWorkerSocketPolicy, ProtocolPolicyIntent,
    ResolvedDisconnectContract, ResolvedSocketPolicy, SocketCreationPath, SocketLifecycleContext,
    SocketPathContext, SocketPlatform, SocketPolicyContext, SocketPolicyRequest,
    SocketReresolveMode, SocketReuseCapability, SocketRole, StartupPeerMode, TimeoutAction,
    UpstreamReresolveCapability, inferred_socket_creation_path, resolve_peer_verification,
    resolve_receive_header_mode, resolve_socket_policy, socket_disconnect_evidence,
};
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Type};

#[inline]
pub fn upstream_reresolve_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    debug_unconnected: bool,
    family: Domain,
) -> UpstreamReresolveCapability {
    let creation_path = inferred_socket_creation_path(proto, sock_type, family);
    let fingerprint = DisconnectRealityKey {
        platform: SocketPlatform::current(),
        family,
        protocol: proto,
        socket_type: sock_type,
        role: SocketRole::Upstream,
        creation_path,
        bind_shape: SocketLifecycleContext::direct_default().bind_shape,
        reuse_address: false,
        reuse_port: false,
        v6_only: None,
        receive_header: resolve_receive_header_mode(proto, sock_type, family),
        protocol_zero_capture: creation_path == SocketCreationPath::WindowsProtocolZeroCapture,
        bound_interface: None,
        connected_peer_mode: resolve_peer_verification(proto, sock_type),
    };
    upstream_reresolve_capability_from_contract(
        debug_unconnected,
        ResolvedDisconnectContract {
            fingerprint,
            evidence: socket_disconnect_evidence(fingerprint),
        },
    )
}

fn upstream_reresolve_capability_from_contract(
    debug_unconnected: bool,
    disconnect: ResolvedDisconnectContract,
) -> UpstreamReresolveCapability {
    let sock_type = disconnect.fingerprint.socket_type;
    let datagram = sock_type == Type::DGRAM && !debug_unconnected;
    let reresolve_mode = if debug_unconnected {
        SocketReresolveMode::MetadataOnlyWhenUnconnected
    } else if sock_type == Type::RAW
        || datagram && !disconnect.evidence.supports_safe_same_descriptor_relock()
    {
        SocketReresolveMode::ReplaceSocket
    } else {
        SocketReresolveMode::ReconnectInPlace
    };
    UpstreamReresolveCapability {
        disconnect: datagram
            .then_some(disconnect.evidence)
            .and_then(|value| value.measured()),
        reresolve_mode,
    }
}

pub(super) fn upstream_reuse_capability_from_contract(
    debug_unconnected: bool,
    disconnect: ResolvedDisconnectContract,
) -> SocketReuseCapability {
    match upstream_reresolve_capability_from_contract(debug_unconnected, disconnect)
        .reresolve_mode()
    {
        SocketReresolveMode::MetadataOnlyWhenUnconnected => SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
        },
        SocketReresolveMode::ReplaceSocket => SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Connected,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
        },
        SocketReresolveMode::ReconnectInPlace => SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Connected,
            reresolve_mode: SocketReresolveMode::ReconnectInPlace,
        },
        SocketReresolveMode::ProcessExitOnly => SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            reresolve_mode: SocketReresolveMode::ProcessExitOnly,
        },
    }
}

#[inline]
pub fn resolve_socket_policy_with_protocol_intent(
    role: SocketRole,
    protocol_intent: ProtocolPolicyIntent,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
) -> ResolvedSocketPolicy {
    let proto = protocol_intent.protocol();
    resolve_socket_policy_for_creation_path_with_protocol_intent(
        role,
        protocol_intent,
        sock_type,
        timeout_act,
        debug_unconnected,
        SocketPathContext {
            family,
            creation_path: inferred_socket_creation_path(proto, sock_type, family),
        },
    )
}

#[inline]
pub fn resolve_socket_policy_for_creation_path_with_protocol_intent(
    role: SocketRole,
    protocol_intent: ProtocolPolicyIntent,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    path: SocketPathContext,
) -> ResolvedSocketPolicy {
    resolve_socket_policy_for_creation_path_with_lifecycle(
        role,
        protocol_intent,
        sock_type,
        timeout_act,
        debug_unconnected,
        SocketPolicyContext {
            path,
            lifecycle: SocketLifecycleContext::direct_default(),
        },
    )
}

#[inline]
pub fn resolve_socket_policy_for_creation_path_with_lifecycle(
    role: SocketRole,
    protocol_intent: ProtocolPolicyIntent,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    context: SocketPolicyContext,
) -> ResolvedSocketPolicy {
    resolve_socket_policy(SocketPolicyRequest {
        role,
        protocol_intent,
        sock_type,
        timeout_act,
        debug_unconnected,
        family: context.path.family,
        creation_path: context.path.creation_path,
        lifecycle: context.lifecycle,
        listener_worker_policy: None,
    })
}

#[inline]
pub fn resolve_listener_socket_policy_with_protocol_intent(
    protocol_intent: ProtocolPolicyIntent,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
    worker_policy: ListenerWorkerSocketPolicy,
) -> ResolvedSocketPolicy {
    let proto = protocol_intent.protocol();
    resolve_listener_socket_policy_for_creation_path_with_protocol_intent(
        protocol_intent,
        sock_type,
        timeout_act,
        debug_unconnected,
        SocketPathContext {
            family,
            creation_path: inferred_socket_creation_path(proto, sock_type, family),
        },
        worker_policy,
    )
}

#[inline]
pub fn resolve_listener_socket_policy_for_creation_path_with_protocol_intent(
    protocol_intent: ProtocolPolicyIntent,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    path: SocketPathContext,
    worker_policy: ListenerWorkerSocketPolicy,
) -> ResolvedSocketPolicy {
    resolve_listener_socket_policy_for_creation_path_with_lifecycle(
        protocol_intent,
        sock_type,
        timeout_act,
        debug_unconnected,
        SocketPolicyContext {
            path,
            lifecycle: SocketLifecycleContext {
                reuse_address: worker_policy.reuse_address,
                reuse_port: worker_policy.reuse_port,
                ..SocketLifecycleContext::direct_default()
            },
        },
        worker_policy,
    )
}

#[inline]
pub fn resolve_listener_socket_policy_for_creation_path_with_lifecycle(
    protocol_intent: ProtocolPolicyIntent,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    context: SocketPolicyContext,
    worker_policy: ListenerWorkerSocketPolicy,
) -> ResolvedSocketPolicy {
    resolve_socket_policy(SocketPolicyRequest {
        role: SocketRole::Listener,
        protocol_intent,
        sock_type,
        timeout_act,
        debug_unconnected,
        family: context.path.family,
        creation_path: context.path.creation_path,
        lifecycle: context.lifecycle,
        listener_worker_policy: Some(worker_policy),
    })
}
