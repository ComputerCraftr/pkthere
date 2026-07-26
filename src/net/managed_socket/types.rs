use super::ManagedSocketError;
use std::io;
use std::net::SocketAddr;

pub(super) const ASSOCIATION_MODE_BITS: u32 = 3;
pub(super) const ASSOCIATION_MODE_MASK: u64 = (1 << ASSOCIATION_MODE_BITS) - 1;
pub(super) const MAX_ASSOCIATION_EPOCH: u64 = u64::MAX >> ASSOCIATION_MODE_BITS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IoLeaseAcquireError {
    Busy,
    Poisoned,
    Retired,
}

pub(super) fn peer_network_address_matches(requested: SocketAddr, observed: SocketAddr) -> bool {
    match (requested, observed) {
        (SocketAddr::V4(requested), SocketAddr::V4(observed)) => requested.ip() == observed.ip(),
        (SocketAddr::V6(requested), SocketAddr::V6(observed)) => {
            requested.ip() == observed.ip() && requested.scope_id() == observed.scope_id()
        }
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum PublishedAssociationMode {
    Unconnected = 0,
    Connected = 1,
    Poisoned = 2,
    Transitioning = 3,
    Retired = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub(super) struct PublishedAssociation(pub(super) u64);

impl PublishedAssociation {
    pub(super) const fn new(mode: PublishedAssociationMode, epoch: u64) -> Option<Self> {
        if epoch > MAX_ASSOCIATION_EPOCH {
            return None;
        }
        Some(Self((epoch << ASSOCIATION_MODE_BITS) | (mode as u64)))
    }

    pub(super) fn mode(self) -> PublishedAssociationMode {
        match self.0 & ASSOCIATION_MODE_MASK {
            0 => PublishedAssociationMode::Unconnected,
            1 => PublishedAssociationMode::Connected,
            2 => PublishedAssociationMode::Poisoned,
            3 => PublishedAssociationMode::Transitioning,
            4 => PublishedAssociationMode::Retired,
            _ => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "managed socket published an invalid association mode"
                ));
                PublishedAssociationMode::Poisoned
            }
        }
    }

    pub(super) const fn epoch(self) -> u64 {
        self.0 >> ASSOCIATION_MODE_BITS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedSendPath {
    Connected,
    Unconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManagedSendResult {
    pub(crate) length: usize,
    pub(crate) path: ManagedSendPath,
}

impl ManagedSendResult {
    pub(crate) const fn used_unconnected_send(self) -> bool {
        !matches!(self.path, ManagedSendPath::Connected)
    }
}

/// The tracked kernel association of one socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssociationState {
    Unconnected {
        epoch: u64,
    },
    Connected {
        peer: SocketAddr,
        epoch: u64,
    },
    Poisoned {
        operation: AssociationOperation,
        previous_peer: Option<SocketAddr>,
        epoch: u64,
    },
    Retired {
        epoch: u64,
    },
}

impl AssociationState {
    pub(crate) const fn epoch(self) -> u64 {
        match self {
            Self::Unconnected { epoch }
            | Self::Connected { epoch, .. }
            | Self::Poisoned { epoch, .. }
            | Self::Retired { epoch } => epoch,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssociationOperation {
    Connect,
    Disconnect,
    Reconnect,
    Replace,
    PublishMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClearTransitionPhase {
    GateClosed,
    DisconnectAttempted,
    DisconnectVerified,
    DescriptorRetired,
    ReplacementBound,
    Published,
    Poisoned,
}

#[derive(Debug)]
pub(crate) enum DisconnectOutcome {
    ExactDisconnected,
    UnchangedConnected {
        local_after: SocketAddr,
        peer_after: SocketAddr,
        syscall_error: Option<io::Error>,
    },
    ChangedUnexpectedly {
        local_after: SocketAddr,
        peer_after: Option<SocketAddr>,
        syscall_error: Option<io::Error>,
    },
    Indeterminate {
        source: io::Error,
        syscall_error: Option<io::Error>,
    },
}

pub(super) fn next_association_epoch(
    current: AssociationState,
    operation: AssociationOperation,
    epoch: u64,
) -> Result<u64, ManagedSocketError> {
    epoch
        .checked_add(1)
        .filter(|next| *next <= MAX_ASSOCIATION_EPOCH)
        .ok_or(ManagedSocketError::EpochExhausted { operation, current })
}

pub(super) fn peer_absent_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::NotConnected | io::ErrorKind::InvalidInput | io::ErrorKind::AddrNotAvailable
    ) {
        return true;
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{WSAEINVAL, WSAENOTCONN};

        return matches!(error.raw_os_error(), Some(WSAEINVAL) | Some(WSAENOTCONN));
    }

    #[cfg(not(windows))]
    false
}
