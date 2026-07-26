use crate::{
    PeerVerification, SocketCreationPath, SocketPlatform, SocketReresolveMode, SocketRole,
    resolve_peer_verification, resolve_receive_header_mode_for_platform,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::ReceiveHeaderMode;
use socket2::{Domain, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamReresolveCapability {
    pub(crate) disconnect: Option<SocketDisconnectCapability>,
    pub(crate) reresolve_mode: SocketReresolveMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramBindPreservation {
    pub exact_local_bind_preserved: bool,
    pub local_port_preserved: bool,
    pub original_destination_receive_supported: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramPortBindCapability {
    pub concrete_bind: DatagramBindPreservation,
    pub wildcard_bind: DatagramBindPreservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramDisconnectCapability {
    pub association_clear_supported: bool,
    pub reconnect_after_disconnect_supported: bool,
    pub stale_receive_queue_isolated: bool,
    pub ephemeral_port_bind: DatagramPortBindCapability,
    pub fixed_port_bind: DatagramPortBindCapability,
}

/// Exact runtime-observable disconnect contract for one immutable socket path.
///
/// This capability authorizes policy selection only. Every production
/// disconnect still validates its own postconditions before committing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketDisconnectCapability {
    pub association_clear_supported: bool,
    pub exact_local_bind_preserved: bool,
    pub reconnect_after_disconnect_supported: bool,
    pub peer_inspection_supported: bool,
    pub stale_receive_queue_isolated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityUnsupportedReason {
    PlatformPathUnavailable,
    SocketPathDoesNotDisconnect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityUnverifiedReason {
    FingerprintNotMeasured,
    PlatformPathNotMeasured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityEvidenceId {
    DatagramUdpPlatformMatrix,
    LinuxAndroidIcmpDatagram,
    DarwinIcmpDatagram,
    DarwinRawIcmp,
    FreebsdRawIcmp,
    LinuxRawIcmp,
    WindowsRawIcmp,
    WindowsProtocolZeroRaw,
}

/// Evidence state for a capability whose absence must not be represented by
/// fabricated all-false facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityEvidence<T> {
    Measured {
        capability: T,
        evidence_id: CapabilityEvidenceId,
    },
    Unsupported(CapabilityUnsupportedReason),
    Unverified(CapabilityUnverifiedReason),
}

pub type SocketDisconnectEvidence = CapabilityEvidence<SocketDisconnectCapability>;
pub type DatagramDisconnectEvidence = CapabilityEvidence<DatagramDisconnectCapability>;

impl<T: Copy> CapabilityEvidence<T> {
    #[inline]
    pub const fn measured(self) -> Option<T> {
        match self {
            Self::Measured { capability, .. } => Some(capability),
            Self::Unsupported(_) | Self::Unverified(_) => None,
        }
    }
}

impl SocketDisconnectEvidence {
    #[inline]
    pub const fn supports_safe_same_descriptor_relock(self) -> bool {
        matches!(
            self,
            Self::Measured { capability, .. }
                if capability.supports_safe_same_descriptor_relock()
        )
    }
}

impl SocketDisconnectCapability {
    #[inline]
    pub const fn supports_safe_same_descriptor_relock(self) -> bool {
        self.association_clear_supported
            && self.exact_local_bind_preserved
            && self.reconnect_after_disconnect_supported
            && self.peer_inspection_supported
            && self.stale_receive_queue_isolated
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectBindShape {
    ConcreteEphemeral,
    ConcreteFixed,
    WildcardEphemeral,
    WildcardFixed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceBindingKind {
    Address,
    Device,
    InterfaceIndex,
}

/// Fingerprint for disconnect evidence. Evidence for one value must never
/// authorize a socket with a different behavior-relevant configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisconnectRealityKey {
    pub platform: SocketPlatform,
    pub family: Domain,
    pub protocol: SupportedProtocol,
    pub socket_type: Type,
    pub role: SocketRole,
    pub creation_path: SocketCreationPath,
    pub bind_shape: DisconnectBindShape,
    pub reuse_address: bool,
    pub reuse_port: bool,
    pub v6_only: Option<bool>,
    pub receive_header: ReceiveHeaderMode,
    pub protocol_zero_capture: bool,
    pub bound_interface: Option<InterfaceBindingKind>,
    pub connected_peer_mode: PeerVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedDisconnectContract {
    pub fingerprint: DisconnectRealityKey,
    pub evidence: SocketDisconnectEvidence,
}

pub fn socket_disconnect_evidence(key: DisconnectRealityKey) -> SocketDisconnectEvidence {
    let protocol_zero_capture = key.creation_path == SocketCreationPath::WindowsProtocolZeroCapture;
    if key.reuse_address
        || key.reuse_port
        || key.v6_only.is_some()
        || key.protocol_zero_capture != protocol_zero_capture
        || key.bound_interface.is_some()
        || key.connected_peer_mode != resolve_peer_verification(key.protocol, key.socket_type)
        || key.receive_header
            != resolve_receive_header_mode_for_platform(
                key.platform,
                key.protocol,
                key.socket_type,
                key.family,
            )
    {
        return CapabilityEvidence::Unverified(CapabilityUnverifiedReason::FingerprintNotMeasured);
    }

    match (key.protocol, key.socket_type, key.creation_path) {
        (SupportedProtocol::UDP, Type::DGRAM, SocketCreationPath::Datagram) => {
            if key.platform == SocketPlatform::Other {
                return CapabilityEvidence::Unverified(
                    CapabilityUnverifiedReason::PlatformPathNotMeasured,
                );
            }
            let capability =
                measured_datagram_disconnect_capability_for(key.platform, key.protocol, key.family);
            let bind = match key.bind_shape {
                DisconnectBindShape::ConcreteEphemeral => {
                    capability.ephemeral_port_bind.concrete_bind
                }
                DisconnectBindShape::ConcreteFixed => capability.fixed_port_bind.concrete_bind,
                DisconnectBindShape::WildcardEphemeral => {
                    capability.ephemeral_port_bind.wildcard_bind
                }
                DisconnectBindShape::WildcardFixed => capability.fixed_port_bind.wildcard_bind,
            };
            CapabilityEvidence::Measured {
                capability: SocketDisconnectCapability {
                    association_clear_supported: capability.association_clear_supported,
                    exact_local_bind_preserved: bind.exact_local_bind_preserved,
                    reconnect_after_disconnect_supported: capability
                        .reconnect_after_disconnect_supported
                        && bind.exact_local_bind_preserved,
                    peer_inspection_supported: capability.association_clear_supported,
                    stale_receive_queue_isolated: capability.stale_receive_queue_isolated,
                },
                evidence_id: CapabilityEvidenceId::DatagramUdpPlatformMatrix,
            }
        }
        (SupportedProtocol::ICMP, Type::DGRAM, SocketCreationPath::Datagram) => {
            match key.platform {
                SocketPlatform::Linux | SocketPlatform::Android => CapabilityEvidence::Measured {
                    capability: SocketDisconnectCapability {
                        association_clear_supported: true,
                        exact_local_bind_preserved: false,
                        reconnect_after_disconnect_supported: false,
                        peer_inspection_supported: true,
                        stale_receive_queue_isolated: false,
                    },
                    evidence_id: CapabilityEvidenceId::LinuxAndroidIcmpDatagram,
                },
                SocketPlatform::Macos | SocketPlatform::Ios => CapabilityEvidence::Measured {
                    capability: SocketDisconnectCapability {
                        association_clear_supported: true,
                        exact_local_bind_preserved: true,
                        reconnect_after_disconnect_supported: false,
                        peer_inspection_supported: true,
                        stale_receive_queue_isolated: false,
                    },
                    evidence_id: CapabilityEvidenceId::DarwinIcmpDatagram,
                },
                SocketPlatform::Windows | SocketPlatform::Freebsd => {
                    CapabilityEvidence::Unsupported(
                        CapabilityUnsupportedReason::PlatformPathUnavailable,
                    )
                }
                SocketPlatform::Other => CapabilityEvidence::Unverified(
                    CapabilityUnverifiedReason::PlatformPathNotMeasured,
                ),
            }
        }
        (SupportedProtocol::ICMP, Type::RAW, SocketCreationPath::RawIcmp) => {
            // Ordinary RAW sockets connect at layer 3. Darwin reality proves
            // that the peer clears and the concrete bind survives, but not
            // reconnect or queued-packet isolation. Recording those measured
            // facts keeps policy/evidence parity without authorizing
            // same-descriptor relock. Protocol-zero capture is excluded above.
            match key.platform {
                SocketPlatform::Macos | SocketPlatform::Ios => CapabilityEvidence::Measured {
                    capability: SocketDisconnectCapability {
                        association_clear_supported: true,
                        exact_local_bind_preserved: true,
                        reconnect_after_disconnect_supported: false,
                        peer_inspection_supported: true,
                        stale_receive_queue_isolated: false,
                    },
                    evidence_id: CapabilityEvidenceId::DarwinRawIcmp,
                },
                SocketPlatform::Linux => CapabilityEvidence::Measured {
                    capability: SocketDisconnectCapability {
                        association_clear_supported: false,
                        exact_local_bind_preserved: false,
                        reconnect_after_disconnect_supported: false,
                        peer_inspection_supported: false,
                        stale_receive_queue_isolated: false,
                    },
                    evidence_id: CapabilityEvidenceId::LinuxRawIcmp,
                },
                SocketPlatform::Windows | SocketPlatform::Freebsd => CapabilityEvidence::Measured {
                    capability: measured_reconnectable_raw_disconnect(),
                    evidence_id: if key.platform == SocketPlatform::Windows {
                        CapabilityEvidenceId::WindowsRawIcmp
                    } else {
                        CapabilityEvidenceId::FreebsdRawIcmp
                    },
                },
                SocketPlatform::Android | SocketPlatform::Other => CapabilityEvidence::Unverified(
                    CapabilityUnverifiedReason::PlatformPathNotMeasured,
                ),
            }
        }
        (SupportedProtocol::ICMP, Type::RAW, SocketCreationPath::WindowsProtocolZeroCapture) => {
            if key.platform == SocketPlatform::Windows && key.family == Domain::IPV4 {
                CapabilityEvidence::Measured {
                    capability: measured_reconnectable_raw_disconnect(),
                    evidence_id: CapabilityEvidenceId::WindowsProtocolZeroRaw,
                }
            } else {
                CapabilityEvidence::Unverified(CapabilityUnverifiedReason::FingerprintNotMeasured)
            }
        }
        _ => CapabilityEvidence::Unsupported(
            CapabilityUnsupportedReason::SocketPathDoesNotDisconnect,
        ),
    }
}

impl DatagramDisconnectCapability {
    pub const fn supports_safe_same_descriptor_relock(self) -> bool {
        self.association_clear_supported
            && self.reconnect_after_disconnect_supported
            && self.stale_receive_queue_isolated
            && self.preserves_every_requested_bind()
    }

    pub const fn preserves_every_requested_bind(self) -> bool {
        self.ephemeral_port_bind
            .concrete_bind
            .exact_local_bind_preserved
            && self
                .ephemeral_port_bind
                .wildcard_bind
                .exact_local_bind_preserved
            && self
                .fixed_port_bind
                .concrete_bind
                .exact_local_bind_preserved
            && self
                .fixed_port_bind
                .wildcard_bind
                .exact_local_bind_preserved
    }
}

impl UpstreamReresolveCapability {
    pub const fn can_disconnect(self) -> bool {
        matches!(
            self.disconnect,
            Some(capability) if capability.association_clear_supported
        )
    }

    pub const fn can_reconnect_to_new_target(self) -> bool {
        matches!(self.reresolve_mode, SocketReresolveMode::ReconnectInPlace)
    }

    pub const fn reresolve_mode(self) -> SocketReresolveMode {
        self.reresolve_mode
    }
}

#[inline]
pub fn datagram_disconnect_evidence(
    proto: SupportedProtocol,
    family: Domain,
) -> DatagramDisconnectEvidence {
    datagram_disconnect_evidence_for(SocketPlatform::current(), proto, family)
}

#[inline]
pub fn datagram_disconnect_evidence_for(
    platform: SocketPlatform,
    proto: SupportedProtocol,
    family: Domain,
) -> DatagramDisconnectEvidence {
    if proto != SupportedProtocol::UDP || (family != Domain::IPV4 && family != Domain::IPV6) {
        return CapabilityEvidence::Unsupported(
            CapabilityUnsupportedReason::SocketPathDoesNotDisconnect,
        );
    }
    if platform == SocketPlatform::Other {
        return CapabilityEvidence::Unverified(CapabilityUnverifiedReason::PlatformPathNotMeasured);
    }
    CapabilityEvidence::Measured {
        capability: measured_datagram_disconnect_capability_for(platform, proto, family),
        evidence_id: CapabilityEvidenceId::DatagramUdpPlatformMatrix,
    }
}

fn measured_datagram_disconnect_capability_for(
    platform: SocketPlatform,
    proto: SupportedProtocol,
    family: Domain,
) -> DatagramDisconnectCapability {
    let supported_family = family == Domain::IPV4 || family == Domain::IPV6;
    let measured_udp = proto == SupportedProtocol::UDP
        && supported_family
        && matches!(
            platform,
            SocketPlatform::Linux
                | SocketPlatform::Android
                | SocketPlatform::Macos
                | SocketPlatform::Ios
                | SocketPlatform::Windows
                | SocketPlatform::Freebsd
        );
    // ICMP DGRAM sockets have different kernel identity and bind semantics.
    // Do not inherit UDP disconnect evidence without an ICMP-specific probe.
    let association_clear_supported = measured_udp;
    let darwin = matches!(platform, SocketPlatform::Macos | SocketPlatform::Ios);
    let freebsd = platform == SocketPlatform::Freebsd;
    let unavailable = DatagramBindPreservation {
        exact_local_bind_preserved: false,
        local_port_preserved: false,
        original_destination_receive_supported: false,
    };
    let darwin_concrete = DatagramBindPreservation {
        // Darwin retains the port but widens a concrete IP bind to wildcard.
        exact_local_bind_preserved: false,
        local_port_preserved: association_clear_supported && darwin,
        original_destination_receive_supported: association_clear_supported && darwin,
    };
    let preserved = DatagramBindPreservation {
        exact_local_bind_preserved: association_clear_supported,
        local_port_preserved: association_clear_supported,
        original_destination_receive_supported: association_clear_supported,
    };
    let windows = platform == SocketPlatform::Windows;
    let ephemeral_port_bind = if darwin {
        DatagramPortBindCapability {
            concrete_bind: darwin_concrete,
            wildcard_bind: preserved,
        }
    } else if freebsd {
        DatagramPortBindCapability {
            concrete_bind: DatagramBindPreservation {
                exact_local_bind_preserved: false,
                local_port_preserved: true,
                original_destination_receive_supported: false,
            },
            wildcard_bind: DatagramBindPreservation {
                original_destination_receive_supported: false,
                ..preserved
            },
        }
    } else if windows {
        DatagramPortBindCapability {
            concrete_bind: preserved,
            wildcard_bind: preserved,
        }
    } else {
        // Linux forgets an ephemeral bind's realized port on disconnect,
        // regardless of whether its requested IP was concrete or wildcard.
        DatagramPortBindCapability {
            concrete_bind: unavailable,
            wildcard_bind: unavailable,
        }
    };
    let fixed_port_bind = if darwin {
        DatagramPortBindCapability {
            concrete_bind: darwin_concrete,
            wildcard_bind: preserved,
        }
    } else if freebsd {
        ephemeral_port_bind
    } else {
        // Linux preserves an explicitly requested nonzero bind exactly.
        DatagramPortBindCapability {
            concrete_bind: preserved,
            wildcard_bind: preserved,
        }
    };

    DatagramDisconnectCapability {
        association_clear_supported,
        reconnect_after_disconnect_supported: association_clear_supported,
        // UDP has no protocol session identity. Existing datagrams can remain
        // queued across disconnect/reconnect, so descriptor reuse is not a
        // safe relock authority without independent queue-isolation evidence.
        stale_receive_queue_isolated: false,
        ephemeral_port_bind: if association_clear_supported {
            ephemeral_port_bind
        } else {
            DatagramPortBindCapability {
                concrete_bind: unavailable,
                wildcard_bind: unavailable,
            }
        },
        fixed_port_bind: if association_clear_supported {
            fixed_port_bind
        } else {
            DatagramPortBindCapability {
                concrete_bind: unavailable,
                wildcard_bind: unavailable,
            }
        },
    }
}

const fn measured_reconnectable_raw_disconnect() -> SocketDisconnectCapability {
    SocketDisconnectCapability {
        association_clear_supported: true,
        exact_local_bind_preserved: true,
        reconnect_after_disconnect_supported: true,
        peer_inspection_supported: true,
        stale_receive_queue_isolated: false,
    }
}
