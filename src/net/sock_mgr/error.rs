#[cfg(all(test, not(miri)))]
use crate::net::managed_socket::ManagedSocketError;
use std::fmt;
use std::io;

use super::StateVersion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    NotRequired,
    Restored,
    Replaced,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransactionLeg {
    Listener,
    Upstream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactionJournalEntry {
    pub(crate) socket_slot: u32,
    pub(crate) leg: TransactionLeg,
    pub(crate) transition_attempted: bool,
    pub(crate) transition_completed: bool,
    pub(crate) recovery: RecoveryOutcome,
    pub(crate) forced_replacement: bool,
    pub(crate) recovery_version: Option<StateVersion>,
}

#[derive(Debug)]
pub(crate) enum ManagerError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    #[cfg(all(test, not(miri)))]
    SocketTransition {
        operation: &'static str,
        source: ManagedSocketError,
    },
    VersionExhausted {
        current: StateVersion,
    },
    TransactionFailed {
        operation: &'static str,
        cause: String,
        journal: Vec<TransactionJournalEntry>,
    },
}

impl ManagerError {
    pub(crate) const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) const fn socket(operation: &'static str, source: ManagedSocketError) -> Self {
        Self::SocketTransition { operation, source }
    }
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            #[cfg(all(test, not(miri)))]
            Self::SocketTransition { operation, source } => {
                write!(formatter, "{operation}: {source}")
            }
            Self::VersionExhausted { current } => {
                write!(formatter, "socket-manager version {current} is exhausted")
            }
            Self::TransactionFailed {
                operation,
                cause,
                journal,
            } => write!(
                formatter,
                "{operation} failed: {cause}; recovery journal: {journal:?}"
            ),
        }
    }
}

impl std::error::Error for ManagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            #[cfg(all(test, not(miri)))]
            Self::SocketTransition { source, .. } => Some(source),
            Self::VersionExhausted { .. } | Self::TransactionFailed { .. } => None,
        }
    }
}
