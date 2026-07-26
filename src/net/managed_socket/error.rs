use super::{AssociationOperation, AssociationState};
use std::fmt;
use std::io;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AssociationStale {
    expected_epoch: u64,
}

impl AssociationStale {
    pub(crate) const fn new(expected_epoch: u64) -> Self {
        Self { expected_epoch }
    }

    pub(crate) const fn expected_epoch(self) -> u64 {
        self.expected_epoch
    }

    pub(crate) fn from_io(error: &io::Error) -> Option<Self> {
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<Self>())
            .copied()
    }
}

impl fmt::Display for AssociationStale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "kernel rejected connected send at association epoch {} without sending data",
            self.expected_epoch
        )
    }
}

impl std::error::Error for AssociationStale {}

#[derive(Debug)]
pub(crate) enum ManagedSocketError {
    InvalidTransition {
        operation: AssociationOperation,
        current: AssociationState,
    },
    UnexpectedInitialAssociation {
        expected_peer: Option<SocketAddr>,
        observed_peer: Option<SocketAddr>,
    },
    Syscall {
        operation: AssociationOperation,
        source: io::Error,
    },
    Poisoned {
        operation: AssociationOperation,
        poisoned_by: AssociationOperation,
        epoch: u64,
    },
    EpochExhausted {
        operation: AssociationOperation,
        current: AssociationState,
    },
    PublishedAssociationExhausted {
        epoch: u64,
    },
    ActiveIoExhausted,
    TopologyQuiescenceLost {
        operation: AssociationOperation,
        active_io: usize,
        epoch: u64,
    },
    TopologyReservationLost {
        operation: AssociationOperation,
    },
    PublicationAuthorityLost {
        source: crate::authority::AuthorityError,
    },
    AuthorityIdentityConflict {
        expected_flow: u64,
        expected_direction: u8,
        expected_generation: u64,
        observed_flow: u64,
        observed_direction: u8,
        observed_generation: u64,
    },
    DescriptorOwnershipLost {
        stage: &'static str,
    },
    DescriptorAuthorityLost {
        source: crate::authority::AuthorityError,
    },
    DescriptorOwnershipEscaped {
        strong_count: usize,
    },
    DescriptorRevocationExhausted,
    DescriptorRevocationTimedOut {
        generation: u64,
    },
    DisconnectUnchanged {
        local: SocketAddr,
        peer: SocketAddr,
        syscall_error: Option<String>,
    },
    DisconnectChangedUnexpectedly {
        local: SocketAddr,
        peer: Option<SocketAddr>,
        syscall_error: Option<String>,
    },
    DisconnectIndeterminate {
        cause: String,
        syscall_error: Option<String>,
    },
    Retired {
        operation: AssociationOperation,
        epoch: u64,
    },
    NonblockingSetup(io::Error),
    PeerInspection(io::Error),
}

impl fmt::Display for ManagedSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { operation, current } => write!(
                formatter,
                "{operation:?} is invalid for managed socket state {current:?}"
            ),
            Self::UnexpectedInitialAssociation {
                expected_peer,
                observed_peer,
            } => write!(
                formatter,
                "managed socket initial association mismatch: expected {expected_peer:?}, observed {observed_peer:?}"
            ),
            Self::Syscall { operation, source } => {
                write!(
                    formatter,
                    "{operation:?} socket transition failed: {source}"
                )
            }
            Self::Poisoned {
                operation,
                poisoned_by,
                epoch,
            } => write!(
                formatter,
                "{operation:?} rejected: socket was poisoned by {poisoned_by:?} at epoch {epoch}"
            ),
            Self::EpochExhausted { operation, current } => write!(
                formatter,
                "{operation:?} rejected: managed socket association epoch exhausted in {current:?}"
            ),
            Self::PublishedAssociationExhausted { epoch } => write!(
                formatter,
                "managed socket association epoch {epoch} cannot be encoded for publication"
            ),
            Self::ActiveIoExhausted => {
                write!(formatter, "managed socket active I/O lease count exhausted")
            }
            Self::TopologyQuiescenceLost {
                operation,
                active_io,
                epoch,
            } => write!(
                formatter,
                "{operation:?} lost topology quiescence at epoch {epoch} with {active_io} active I/O lease(s)"
            ),
            Self::TopologyReservationLost { operation } => write!(
                formatter,
                "{operation:?} lost the managed socket topology reservation"
            ),
            Self::PublicationAuthorityLost { source } => write!(
                formatter,
                "managed socket publication authority was lost: {source}"
            ),
            Self::AuthorityIdentityConflict {
                expected_flow,
                expected_direction,
                expected_generation,
                observed_flow,
                observed_direction,
                observed_generation,
            } => write!(
                formatter,
                "managed socket authority identity conflict: expected ({expected_flow}, {expected_direction}, {expected_generation}), observed ({observed_flow}, {observed_direction}, {observed_generation})"
            ),
            Self::DescriptorOwnershipLost { stage } => {
                write!(
                    formatter,
                    "managed socket descriptor ownership was lost during {stage}"
                )
            }
            Self::DescriptorAuthorityLost { source } => {
                write!(
                    formatter,
                    "managed socket descriptor authority was lost: {source}"
                )
            }
            Self::DescriptorOwnershipEscaped { strong_count } => write!(
                formatter,
                "managed socket descriptor ownership escaped after I/O drain: strong_count={strong_count}"
            ),
            Self::DescriptorRevocationExhausted => {
                write!(
                    formatter,
                    "managed socket descriptor revocation generation exhausted"
                )
            }
            Self::DescriptorRevocationTimedOut { generation } => write!(
                formatter,
                "managed socket descriptor revocation generation {generation} was not acknowledged before the topology deadline"
            ),
            Self::DisconnectUnchanged {
                local,
                peer,
                syscall_error,
            } => write!(
                formatter,
                "disconnect left the original connected topology unchanged: local={local}, peer={peer}, syscall_error={syscall_error:?}"
            ),
            Self::DisconnectChangedUnexpectedly {
                local,
                peer,
                syscall_error,
            } => write!(
                formatter,
                "disconnect irreversibly changed the socket outside its required contract: local={local}, peer={peer:?}, syscall_error={syscall_error:?}"
            ),
            Self::DisconnectIndeterminate {
                cause,
                syscall_error,
            } => write!(
                formatter,
                "disconnect postconditions are indeterminate: {cause}; syscall_error={syscall_error:?}"
            ),
            Self::Retired { operation, epoch } => write!(
                formatter,
                "{operation:?} rejected: socket was retired at epoch {epoch}"
            ),
            Self::NonblockingSetup(source) => {
                write!(
                    formatter,
                    "could not enable nonblocking socket I/O: {source}"
                )
            }
            Self::PeerInspection(source) => {
                write!(
                    formatter,
                    "could not inspect kernel peer association: {source}"
                )
            }
        }
    }
}

impl std::error::Error for ManagedSocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syscall { source, .. }
            | Self::NonblockingSetup(source)
            | Self::PeerInspection(source) => Some(source),
            Self::PublicationAuthorityLost { source }
            | Self::DescriptorAuthorityLost { source } => Some(source),
            Self::InvalidTransition { .. }
            | Self::UnexpectedInitialAssociation { .. }
            | Self::Poisoned { .. }
            | Self::EpochExhausted { .. }
            | Self::PublishedAssociationExhausted { .. }
            | Self::ActiveIoExhausted
            | Self::TopologyQuiescenceLost { .. }
            | Self::TopologyReservationLost { .. }
            | Self::AuthorityIdentityConflict { .. }
            | Self::DescriptorOwnershipLost { .. }
            | Self::DescriptorOwnershipEscaped { .. }
            | Self::DescriptorRevocationExhausted
            | Self::DescriptorRevocationTimedOut { .. }
            | Self::DisconnectUnchanged { .. }
            | Self::DisconnectChangedUnexpectedly { .. }
            | Self::DisconnectIndeterminate { .. }
            | Self::Retired { .. } => None,
        }
    }
}

impl ManagedSocketError {
    pub(crate) const fn is_fatal_topology_invariant(&self) -> bool {
        matches!(
            self,
            Self::TopologyQuiescenceLost { .. }
                | Self::TopologyReservationLost { .. }
                | Self::EpochExhausted { .. }
                | Self::ActiveIoExhausted
                | Self::DescriptorOwnershipLost { .. }
                | Self::DescriptorAuthorityLost { .. }
                | Self::DescriptorOwnershipEscaped { .. }
                | Self::DescriptorRevocationExhausted
                | Self::DescriptorRevocationTimedOut { .. }
                | Self::DisconnectChangedUnexpectedly { .. }
                | Self::DisconnectIndeterminate { .. }
        )
    }
}
