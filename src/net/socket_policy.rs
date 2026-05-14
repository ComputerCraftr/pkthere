use crate::cli::{SupportedProtocol, TimeoutAction};
use socket2::Type;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketRole {
    Listener,
    Upstream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartupPeerMode {
    Connected,
    Unconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockedPeerMode {
    ConnectAfterLock,
    StayUnconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketReresolveMode {
    ReconnectInPlace,
    ReplaceSocket,
    MetadataOnlyWhenUnconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimeoutClearMode {
    DisconnectSocket,
    ProcessExit,
    NoConnectedState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketReuseCapability {
    pub startup_peer_mode: StartupPeerMode,
    pub locked_peer_mode: LockedPeerMode,
    pub reresolve_mode: SocketReresolveMode,
    pub timeout_clear_mode: TimeoutClearMode,
}

impl SocketReuseCapability {
    #[inline]
    pub(crate) const fn starts_connected(self) -> bool {
        matches!(self.startup_peer_mode, StartupPeerMode::Connected)
    }

    #[inline]
    pub(crate) const fn connects_after_lock(self) -> bool {
        matches!(self.locked_peer_mode, LockedPeerMode::ConnectAfterLock)
    }

    #[inline]
    pub(crate) const fn reconnects_in_place(self) -> bool {
        matches!(self.reresolve_mode, SocketReresolveMode::ReconnectInPlace)
    }
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
        SocketRole::Upstream => upstream_reuse_capability(proto, sock_type, debug_unconnected),
    }
}

fn listener_reuse_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
) -> SocketReuseCapability {
    if debug_unconnected || proto == SupportedProtocol::ICMP || sock_type == Type::RAW {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            locked_peer_mode: LockedPeerMode::StayUnconnected,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
            timeout_clear_mode: TimeoutClearMode::NoConnectedState,
        }
    } else {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            locked_peer_mode: if timeout_act == TimeoutAction::Exit
                || cfg!(not(target_os = "freebsd"))
            {
                LockedPeerMode::ConnectAfterLock
            } else {
                LockedPeerMode::StayUnconnected
            },
            reresolve_mode: if timeout_act == TimeoutAction::Exit
                || cfg!(not(target_os = "freebsd"))
            {
                SocketReresolveMode::ReconnectInPlace
            } else {
                SocketReresolveMode::ReplaceSocket
            },
            timeout_clear_mode: if timeout_act == TimeoutAction::Exit {
                TimeoutClearMode::ProcessExit
            } else if cfg!(target_os = "freebsd") {
                TimeoutClearMode::NoConnectedState
            } else {
                TimeoutClearMode::DisconnectSocket
            },
        }
    }
}

fn upstream_reuse_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    debug_unconnected: bool,
) -> SocketReuseCapability {
    if cfg!(windows) && proto == SupportedProtocol::ICMP && sock_type == Type::RAW {
        return SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Connected,
            locked_peer_mode: LockedPeerMode::ConnectAfterLock,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
            timeout_clear_mode: TimeoutClearMode::ProcessExit,
        };
    }

    if debug_unconnected {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            locked_peer_mode: LockedPeerMode::StayUnconnected,
            reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
            timeout_clear_mode: TimeoutClearMode::NoConnectedState,
        }
    } else if sock_type == Type::RAW {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Connected,
            locked_peer_mode: LockedPeerMode::ConnectAfterLock,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
            timeout_clear_mode: TimeoutClearMode::ProcessExit,
        }
    } else {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Connected,
            locked_peer_mode: LockedPeerMode::ConnectAfterLock,
            reresolve_mode: SocketReresolveMode::ReconnectInPlace,
            timeout_clear_mode: TimeoutClearMode::ProcessExit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LockedPeerMode, SocketReresolveMode, SocketReuseCapability, SocketRole, StartupPeerMode,
        TimeoutClearMode, socket_reuse_capability,
    };
    use crate::cli::{SupportedProtocol, TimeoutAction};
    use socket2::Type;

    fn assert_capability(actual: SocketReuseCapability, expected: SocketReuseCapability) {
        assert_eq!(actual, expected);
    }

    #[test]
    fn listener_udp_dgram_matrix_tracks_timeout_and_freebsd_policy() {
        let exit_policy = socket_reuse_capability(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Exit,
            false,
        );
        assert_capability(
            exit_policy,
            SocketReuseCapability {
                startup_peer_mode: StartupPeerMode::Unconnected,
                locked_peer_mode: LockedPeerMode::ConnectAfterLock,
                reresolve_mode: SocketReresolveMode::ReconnectInPlace,
                timeout_clear_mode: TimeoutClearMode::ProcessExit,
            },
        );

        let drop_policy = socket_reuse_capability(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
        );
        let (locked_peer_mode, reresolve_mode, timeout_clear_mode) = if cfg!(target_os = "freebsd")
        {
            (
                LockedPeerMode::StayUnconnected,
                SocketReresolveMode::ReplaceSocket,
                TimeoutClearMode::NoConnectedState,
            )
        } else {
            (
                LockedPeerMode::ConnectAfterLock,
                SocketReresolveMode::ReconnectInPlace,
                TimeoutClearMode::DisconnectSocket,
            )
        };
        assert_capability(
            drop_policy,
            SocketReuseCapability {
                startup_peer_mode: StartupPeerMode::Unconnected,
                locked_peer_mode,
                reresolve_mode,
                timeout_clear_mode,
            },
        );
    }

    #[test]
    fn listener_raw_icmp_exit_stays_unconnected_and_not_reconnectable() {
        let policy = socket_reuse_capability(
            SocketRole::Listener,
            SupportedProtocol::ICMP,
            Type::RAW,
            TimeoutAction::Exit,
            false,
        );
        assert_capability(
            policy,
            SocketReuseCapability {
                startup_peer_mode: StartupPeerMode::Unconnected,
                locked_peer_mode: LockedPeerMode::StayUnconnected,
                reresolve_mode: SocketReresolveMode::ReplaceSocket,
                timeout_clear_mode: TimeoutClearMode::NoConnectedState,
            },
        );
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
            assert_eq!(listener.locked_peer_mode, LockedPeerMode::StayUnconnected);
            assert_eq!(
                upstream.reresolve_mode,
                SocketReresolveMode::ReconnectInPlace
            );
            assert_eq!(listener.startup_peer_mode, StartupPeerMode::Unconnected);
            assert_eq!(upstream.startup_peer_mode, StartupPeerMode::Connected);
        }

        #[cfg(not(target_os = "freebsd"))]
        {
            assert_eq!(
                listener.reresolve_mode,
                SocketReresolveMode::ReconnectInPlace
            );
            assert_eq!(
                upstream.reresolve_mode,
                SocketReresolveMode::ReconnectInPlace
            );
            assert_eq!(listener.startup_peer_mode, StartupPeerMode::Unconnected);
            assert_eq!(upstream.startup_peer_mode, StartupPeerMode::Connected);
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
        assert_capability(
            policy,
            SocketReuseCapability {
                startup_peer_mode: StartupPeerMode::Connected,
                locked_peer_mode: LockedPeerMode::ConnectAfterLock,
                reresolve_mode: SocketReresolveMode::ReplaceSocket,
                timeout_clear_mode: TimeoutClearMode::ProcessExit,
            },
        );
    }

    #[test]
    fn windows_raw_icmp_upstream_preserves_connected_rcvall_path() {
        let policy = socket_reuse_capability(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            Type::RAW,
            TimeoutAction::Drop,
            true,
        );

        #[cfg(windows)]
        {
            assert_eq!(policy.startup_peer_mode, StartupPeerMode::Connected);
        }

        #[cfg(not(windows))]
        {
            assert_eq!(policy.startup_peer_mode, StartupPeerMode::Unconnected);
        }
    }

    #[test]
    fn udp_upstream_debug_unconnected_uses_metadata_only_policy() {
        let policy = socket_reuse_capability(
            SocketRole::Upstream,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            true,
        );

        assert_capability(
            policy,
            SocketReuseCapability {
                startup_peer_mode: StartupPeerMode::Unconnected,
                locked_peer_mode: LockedPeerMode::StayUnconnected,
                reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
                timeout_clear_mode: TimeoutClearMode::NoConnectedState,
            },
        );
    }

    #[test]
    fn dgram_upstream_protocols_share_connected_default_and_debug_override() {
        for proto in [SupportedProtocol::UDP, SupportedProtocol::ICMP] {
            let default_policy = socket_reuse_capability(
                SocketRole::Upstream,
                proto,
                Type::DGRAM,
                TimeoutAction::Drop,
                false,
            );
            assert_capability(
                default_policy,
                SocketReuseCapability {
                    startup_peer_mode: StartupPeerMode::Connected,
                    locked_peer_mode: LockedPeerMode::ConnectAfterLock,
                    reresolve_mode: SocketReresolveMode::ReconnectInPlace,
                    timeout_clear_mode: TimeoutClearMode::ProcessExit,
                },
            );

            let debug_policy = socket_reuse_capability(
                SocketRole::Upstream,
                proto,
                Type::DGRAM,
                TimeoutAction::Drop,
                true,
            );
            assert_capability(
                debug_policy,
                SocketReuseCapability {
                    startup_peer_mode: StartupPeerMode::Unconnected,
                    locked_peer_mode: LockedPeerMode::StayUnconnected,
                    reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
                    timeout_clear_mode: TimeoutClearMode::NoConnectedState,
                },
            );
        }
    }

    #[test]
    fn timeout_drop_forces_unconnected_only_when_listener_policy_requires_it() {
        assert_eq!(
            socket_reuse_capability(
                SocketRole::Listener,
                SupportedProtocol::ICMP,
                Type::RAW,
                TimeoutAction::Drop,
                false
            )
            .locked_peer_mode,
            LockedPeerMode::StayUnconnected
        );

        #[cfg(target_os = "freebsd")]
        assert_eq!(
            socket_reuse_capability(
                SocketRole::Listener,
                SupportedProtocol::UDP,
                Type::DGRAM,
                TimeoutAction::Drop,
                false
            )
            .locked_peer_mode,
            LockedPeerMode::StayUnconnected
        );

        #[cfg(not(target_os = "freebsd"))]
        assert_eq!(
            socket_reuse_capability(
                SocketRole::Listener,
                SupportedProtocol::UDP,
                Type::DGRAM,
                TimeoutAction::Drop,
                false
            )
            .locked_peer_mode,
            LockedPeerMode::ConnectAfterLock
        );
    }
}
