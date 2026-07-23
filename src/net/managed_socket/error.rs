use super::{AssociationOperation, AssociationState};
use std::fmt;
use std::io;
use std::net::SocketAddr;

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
            Self::Syscall { source, .. } | Self::PeerInspection(source) => Some(source),
            Self::InvalidTransition { .. }
            | Self::UnexpectedInitialAssociation { .. }
            | Self::Poisoned { .. } => None,
        }
    }
}
