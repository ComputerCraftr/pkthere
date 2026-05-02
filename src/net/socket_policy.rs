use crate::cli::SupportedProtocol;
use socket2::Type;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketRole {
    Listener,
    Upstream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketReuseCapability {
    pub can_keep_connected: bool,
    pub can_reconnect_in_place: bool,
    pub should_start_connected: bool,
}

pub(crate) fn socket_reuse_capability(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
) -> SocketReuseCapability {
    match role {
        SocketRole::Listener => listener_reuse_capability(proto, sock_type),
        SocketRole::Upstream => upstream_reuse_capability(proto, sock_type),
    }
}

fn listener_reuse_capability(proto: SupportedProtocol, sock_type: Type) -> SocketReuseCapability {
    #[cfg(target_os = "freebsd")]
    {
        let _ = proto;
        let _ = sock_type;
        return SocketReuseCapability {
            can_keep_connected: false,
            can_reconnect_in_place: false,
            should_start_connected: false,
        };
    }

    #[cfg(not(target_os = "freebsd"))]
    {
        if proto == SupportedProtocol::ICMP || sock_type == Type::RAW {
            SocketReuseCapability {
                can_keep_connected: false,
                can_reconnect_in_place: false,
                should_start_connected: false,
            }
        } else {
            SocketReuseCapability {
                can_keep_connected: true,
                can_reconnect_in_place: true,
                should_start_connected: true,
            }
        }
    }
}

fn upstream_reuse_capability(_proto: SupportedProtocol, sock_type: Type) -> SocketReuseCapability {
    #[cfg(windows)]
    if _proto == SupportedProtocol::ICMP && sock_type == Type::RAW {
        return SocketReuseCapability {
            can_keep_connected: false,
            can_reconnect_in_place: false,
            should_start_connected: false,
        };
    }

    if sock_type == Type::RAW {
        SocketReuseCapability {
            can_keep_connected: true,
            can_reconnect_in_place: false,
            should_start_connected: true,
        }
    } else {
        SocketReuseCapability {
            can_keep_connected: true,
            can_reconnect_in_place: true,
            should_start_connected: true,
        }
    }
}

#[inline]
pub(crate) fn should_force_listener_unconnected_on_timeout(
    proto: SupportedProtocol,
    sock_type: Type,
) -> bool {
    !socket_reuse_capability(SocketRole::Listener, proto, sock_type).can_keep_connected
}

#[cfg(test)]
mod tests {
    use super::{
        SocketRole, should_force_listener_unconnected_on_timeout, socket_reuse_capability,
    };
    use crate::cli::SupportedProtocol;
    use socket2::Type;

    #[test]
    fn raw_listener_cannot_reconnect_in_place() {
        let policy =
            socket_reuse_capability(SocketRole::Listener, SupportedProtocol::ICMP, Type::RAW);
        assert!(!policy.can_keep_connected);
        assert!(!policy.can_reconnect_in_place);
        assert!(!policy.should_start_connected);
    }

    #[test]
    fn upstream_dgram_reconnect_policy_is_independent_from_listener_policy() {
        let listener =
            socket_reuse_capability(SocketRole::Listener, SupportedProtocol::UDP, Type::DGRAM);
        let upstream =
            socket_reuse_capability(SocketRole::Upstream, SupportedProtocol::UDP, Type::DGRAM);

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
            assert!(listener.should_start_connected);
            assert!(upstream.should_start_connected);
        }
    }

    #[test]
    fn windows_raw_icmp_upstream_starts_unconnected() {
        let policy =
            socket_reuse_capability(SocketRole::Upstream, SupportedProtocol::ICMP, Type::RAW);

        #[cfg(windows)]
        {
            assert!(!policy.can_keep_connected);
            assert!(!policy.can_reconnect_in_place);
            assert!(!policy.should_start_connected);
        }

        #[cfg(not(windows))]
        {
            assert!(policy.can_keep_connected);
            assert!(!policy.can_reconnect_in_place);
            assert!(policy.should_start_connected);
        }
    }

    #[test]
    fn timeout_drop_forces_unconnected_only_when_listener_policy_requires_it() {
        assert!(should_force_listener_unconnected_on_timeout(
            SupportedProtocol::ICMP,
            Type::RAW
        ));

        #[cfg(target_os = "freebsd")]
        assert!(should_force_listener_unconnected_on_timeout(
            SupportedProtocol::UDP,
            Type::DGRAM
        ));

        #[cfg(not(target_os = "freebsd"))]
        assert!(!should_force_listener_unconnected_on_timeout(
            SupportedProtocol::UDP,
            Type::DGRAM
        ));
    }
}
