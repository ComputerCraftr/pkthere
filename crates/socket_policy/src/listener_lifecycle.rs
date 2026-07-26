use super::creation::listener_worker_socket_policy_for;
use super::{
    DisconnectBindShape, DisconnectRealityKey, ListenerClearStrategy, ListenerLockLifecycle,
    ListenerWorkerDistribution, ListenerWorkerSocketPolicy, ResolvedDisconnectContract,
    SocketCreationPath, SocketDisconnectEvidence, SocketPlatform, SocketReresolveMode,
    SupportedProtocol, TimeoutAction, inferred_socket_creation_path, listener_worker_socket_policy,
    resolve_peer_verification, resolve_receive_header_mode, socket_disconnect_evidence,
};
use socket2::{Domain, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerRelockCapability {
    disconnect: SocketDisconnectEvidence,
    pub lifecycle: ListenerLockLifecycle,
}

impl ListenerRelockCapability {
    pub const fn can_lock_connected(self) -> bool {
        self.lifecycle.connects_after_lock()
    }

    pub const fn can_disconnect_lock(self) -> bool {
        self.can_lock_connected()
            && matches!(
                self.disconnect.measured(),
                Some(capability) if capability.association_clear_supported
            )
    }

    pub const fn preserves_original_bind_after_disconnect(self) -> bool {
        matches!(
            self.disconnect.measured(),
            Some(capability) if capability.exact_local_bind_preserved
        )
    }

    pub const fn can_relock_to_new_peer(self) -> bool {
        self.can_lock_connected() && self.disconnect.supports_safe_same_descriptor_relock()
    }

    pub const fn reresolve_mode(self) -> SocketReresolveMode {
        listener_reresolve_mode(self.lifecycle)
    }
}

#[inline]
pub const fn listener_reresolve_mode(lifecycle: ListenerLockLifecycle) -> SocketReresolveMode {
    match lifecycle {
        ListenerLockLifecycle::StayUnconnected
        | ListenerLockLifecycle::StayUnconnectedReplaceOnClear
        | ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::ReplaceOwnerSameBind,
        } => SocketReresolveMode::ReplaceSocket,
        ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::DisconnectToOriginalBind,
        } => SocketReresolveMode::ReconnectInPlace,
        ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::ProcessExit,
        } => SocketReresolveMode::ProcessExitOnly,
    }
}

#[inline]
pub fn listener_relock_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
) -> ListenerRelockCapability {
    listener_relock_capability_with_worker_policy(
        proto,
        sock_type,
        timeout_act,
        debug_unconnected,
        family,
        listener_worker_socket_policy(1, false),
    )
}

#[inline]
pub fn listener_relock_capability_with_worker_policy(
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
    worker_policy: ListenerWorkerSocketPolicy,
) -> ListenerRelockCapability {
    let creation_path = inferred_socket_creation_path(proto, sock_type, family);
    let fingerprint = DisconnectRealityKey {
        platform: SocketPlatform::current(),
        family,
        protocol: proto,
        socket_type: sock_type,
        role: super::SocketRole::Listener,
        creation_path,
        bind_shape: DisconnectBindShape::ConcreteEphemeral,
        reuse_address: worker_policy.reuse_address,
        reuse_port: worker_policy.reuse_port,
        v6_only: None,
        receive_header: resolve_receive_header_mode(proto, sock_type, family),
        protocol_zero_capture: creation_path == SocketCreationPath::WindowsProtocolZeroCapture,
        bound_interface: None,
        connected_peer_mode: resolve_peer_verification(proto, sock_type),
    };
    let contract = ResolvedDisconnectContract {
        fingerprint,
        evidence: socket_disconnect_evidence(fingerprint),
    };
    ListenerRelockCapability {
        disconnect: contract.evidence,
        lifecycle: listener_lock_lifecycle_with_contract(
            proto,
            sock_type,
            timeout_act,
            debug_unconnected,
            family,
            worker_policy,
            contract,
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SameBindReplacementRealityKey {
    pub disconnect: DisconnectRealityKey,
    pub distribution: ListenerWorkerDistribution,
    pub stale_handles_retained: bool,
}

#[inline]
pub fn same_bind_replacement_lifecycle_supported(key: SameBindReplacementRealityKey) -> bool {
    let disconnect = key.disconnect;
    let expected_worker = listener_worker_socket_policy_for(disconnect.platform, 2, false);
    matches!(
        disconnect.platform,
        SocketPlatform::Linux
            | SocketPlatform::Macos
            | SocketPlatform::Windows
            | SocketPlatform::Freebsd
    ) && matches!(disconnect.family, Domain::IPV4 | Domain::IPV6)
        && disconnect.protocol == SupportedProtocol::UDP
        && disconnect.socket_type == Type::DGRAM
        && disconnect.role == super::SocketRole::Listener
        && disconnect.creation_path == SocketCreationPath::Datagram
        && disconnect.reuse_address == expected_worker.reuse_address
        && disconnect.reuse_port == expected_worker.reuse_port
        && disconnect.v6_only.is_none()
        && !disconnect.protocol_zero_capture
        && disconnect.bound_interface.is_none()
        && key.distribution == expected_worker.distribution
        && matches!(key.distribution, ListenerWorkerDistribution::SharedState)
        && key.stale_handles_retained
}

#[inline]
pub fn listener_same_bind_replacement_lifecycle_eligible(
    platform: SocketPlatform,
    family: Domain,
    worker_policy: ListenerWorkerSocketPolicy,
) -> bool {
    same_bind_replacement_lifecycle_supported(SameBindReplacementRealityKey {
        disconnect: DisconnectRealityKey {
            platform,
            family,
            protocol: SupportedProtocol::UDP,
            socket_type: Type::DGRAM,
            role: super::SocketRole::Listener,
            creation_path: SocketCreationPath::Datagram,
            bind_shape: DisconnectBindShape::ConcreteEphemeral,
            reuse_address: worker_policy.reuse_address,
            reuse_port: worker_policy.reuse_port,
            v6_only: None,
            receive_header: super::resolve_receive_header_mode_for_platform(
                platform,
                SupportedProtocol::UDP,
                Type::DGRAM,
                family,
            ),
            protocol_zero_capture: false,
            bound_interface: None,
            connected_peer_mode: resolve_peer_verification(SupportedProtocol::UDP, Type::DGRAM),
        },
        distribution: worker_policy.distribution,
        stale_handles_retained: true,
    })
}

#[inline]
pub fn listener_lock_lifecycle(
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
    worker_policy: ListenerWorkerSocketPolicy,
) -> ListenerLockLifecycle {
    listener_relock_capability_with_worker_policy(
        proto,
        sock_type,
        timeout_act,
        debug_unconnected,
        family,
        worker_policy,
    )
    .lifecycle
}

pub(super) fn listener_lock_lifecycle_with_contract(
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    _family: Domain,
    worker_policy: ListenerWorkerSocketPolicy,
    disconnect: ResolvedDisconnectContract,
) -> ListenerLockLifecycle {
    if proto != SupportedProtocol::UDP || sock_type != Type::DGRAM {
        return ListenerLockLifecycle::StayUnconnected;
    }
    if debug_unconnected {
        return if timeout_act == TimeoutAction::Exit {
            ListenerLockLifecycle::StayUnconnected
        } else {
            ListenerLockLifecycle::StayUnconnectedReplaceOnClear
        };
    }
    if timeout_act == TimeoutAction::Exit {
        return ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::ProcessExit,
        };
    }

    if disconnect.evidence.supports_safe_same_descriptor_relock() {
        return ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::DisconnectToOriginalBind,
        };
    }

    let replacement = SameBindReplacementRealityKey {
        disconnect: disconnect.fingerprint,
        distribution: worker_policy.distribution,
        stale_handles_retained: true,
    };
    if same_bind_replacement_lifecycle_supported(replacement) {
        return ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::ReplaceOwnerSameBind,
        };
    }

    // UDP has no session identity capable of separating stale queued data
    // across a relock. Without exact queue-isolation evidence, clear by
    // descriptor replacement even when the stable listener stays unconnected.
    ListenerLockLifecycle::StayUnconnectedReplaceOnClear
}
