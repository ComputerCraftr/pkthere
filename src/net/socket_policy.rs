use crate::cli::{SupportedProtocol, TimeoutAction};
use socket2::Type;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketRole {
    Listener,
    Upstream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketReuseCapability {
    pub can_keep_connected: bool, // Decides whether to skip watchdog socket disconnect timeout (true if we use timeout exit as our force disconnect)
    pub can_reconnect_in_place: bool, // Decides whether we should connect to a new peer (true if reconnect workflow is exit and restart)
    pub should_start_connected: bool, // Decides whether we should connect on socket construction (listener must wait to connect to peer)
    pub should_bind_wildcard: bool,   // Decides whether the socket should bind an IP or wildcard
}

pub(crate) fn socket_reuse_capability(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
) -> SocketReuseCapability {
    match role {
        SocketRole::Listener => {
            listener_reuse_capability(proto, sock_type, timeout_act, debug_unconnected)
        }
        SocketRole::Upstream => upstream_reuse_capability(sock_type, debug_unconnected),
    }
}

fn listener_reuse_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
) -> SocketReuseCapability {
    if debug_unconnected {
        SocketReuseCapability {
            can_keep_connected: false,
            can_reconnect_in_place: false,
            should_start_connected: false,
            should_bind_wildcard: (proto == SupportedProtocol::ICMP || sock_type == Type::RAW)
                && cfg!(windows),
        }
    } else if proto == SupportedProtocol::ICMP || sock_type == Type::RAW {
        SocketReuseCapability {
            can_keep_connected: timeout_act == TimeoutAction::Exit,
            can_reconnect_in_place: timeout_act == TimeoutAction::Exit,
            should_start_connected: false,
            should_bind_wildcard: cfg!(windows),
        }
    } else {
        SocketReuseCapability {
            can_keep_connected: timeout_act == TimeoutAction::Exit,
            can_reconnect_in_place: timeout_act == TimeoutAction::Exit
                || cfg!(not(target_os = "freebsd")),
            should_start_connected: false,
            should_bind_wildcard: false,
        }
    }
}

fn upstream_reuse_capability(sock_type: Type, debug_unconnected: bool) -> SocketReuseCapability {
    if debug_unconnected {
        SocketReuseCapability {
            can_keep_connected: false,
            can_reconnect_in_place: false,
            should_start_connected: false,
            should_bind_wildcard: sock_type == Type::RAW && cfg!(windows),
        }
    } else if sock_type == Type::RAW {
        SocketReuseCapability {
            can_keep_connected: true,
            can_reconnect_in_place: false,
            should_start_connected: true,
            should_bind_wildcard: cfg!(windows),
        }
    } else {
        SocketReuseCapability {
            can_keep_connected: true,
            can_reconnect_in_place: true,
            should_start_connected: true,
            should_bind_wildcard: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SocketRole, socket_reuse_capability};
    use crate::cli::{SupportedProtocol, TimeoutAction};
    use socket2::Type;

    #[test]
    fn raw_listener_cannot_reconnect_in_place() {
        let policy = socket_reuse_capability(
            SocketRole::Listener,
            SupportedProtocol::ICMP,
            Type::RAW,
            TimeoutAction::Drop,
            false,
        );

        assert!(!policy.can_keep_connected);
        assert!(!policy.can_reconnect_in_place);
        assert!(!policy.should_start_connected);
    }

    #[test]
    fn upstream_dgram_reconnect_policy_is_independent_from_listener_policy() {
        let listener = socket_reuse_capability(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
        );
        let upstream = socket_reuse_capability(
            SocketRole::Upstream,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
        );

        #[cfg(target_os = "freebsd")]
        {
            assert!(!listener.can_reconnect_in_place);
            assert!(upstream.can_reconnect_in_place);
            assert!(!listener.should_start_connected);
            assert!(upstream.should_start_connected);
        }

        #[cfg(not(target_os = "freebsd"))]
        {
            assert!(listener.can_reconnect_in_place);
            assert!(upstream.can_reconnect_in_place);
            assert!(!listener.should_start_connected);
            assert!(upstream.should_start_connected);
        }
    }

    #[test]
    fn raw_icmp_upstream_starts_connected() {
        let policy = socket_reuse_capability(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            Type::RAW,
            TimeoutAction::Drop,
            false,
        );

        assert!(policy.can_keep_connected);
        assert!(!policy.can_reconnect_in_place);
        assert!(policy.should_start_connected);
    }

    #[test]
    fn timeout_drop_forces_unconnected_only_when_listener_policy_requires_it() {
        assert!(
            !socket_reuse_capability(
                SocketRole::Listener,
                SupportedProtocol::ICMP,
                Type::RAW,
                TimeoutAction::Drop,
                false
            )
            .can_reconnect_in_place
        );

        #[cfg(target_os = "freebsd")]
        assert!(
            !socket_reuse_capability(
                SocketRole::Listener,
                SupportedProtocol::UDP,
                Type::DGRAM,
                TimeoutAction::Drop,
                false
            )
            .can_reconnect_in_place
        );

        #[cfg(not(target_os = "freebsd"))]
        assert!(
            socket_reuse_capability(
                SocketRole::Listener,
                SupportedProtocol::UDP,
                Type::DGRAM,
                TimeoutAction::Drop,
                false
            )
            .can_reconnect_in_place
        );
    }
}
