use std::fmt;
use std::io;

use super::StateVersion;
use super::transaction_lock::ReservationError;

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

#[derive(Debug, PartialEq, Eq)]
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
    VersionExhausted {
        current: StateVersion,
    },
    VersionPublicationFailed {
        expected: StateVersion,
        actual: Option<StateVersion>,
    },
    Reservation {
        operation: &'static str,
        cause: ReservationError,
    },
    FlowTopology {
        operation: &'static str,
        cause: crate::flow_state::FlowTopologyError,
    },
    FlowAuthority {
        operation: &'static str,
        cause: crate::flow_state::FlowAuthorityError,
    },
    Poisoned {
        authority: &'static str,
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

    pub(crate) fn class(&self) -> crate::runtime_support::FailureClass {
        use crate::runtime_support::FailureClass;
        match self {
            Self::VersionExhausted { .. }
            | Self::VersionPublicationFailed { .. }
            | Self::Poisoned { .. }
            | Self::TransactionFailed { .. } => FailureClass::FatalInvariant,
            Self::Reservation { cause, .. } => cause.class(),
            Self::FlowTopology { cause, .. } => cause.class(),
            Self::FlowAuthority { cause, .. } => cause.class(),
            Self::Io { source, .. } => {
                let mut current: Option<&(dyn std::error::Error + 'static)> =
                    source.get_ref().map(|error| error as _);
                while let Some(error) = current {
                    if error
                        .downcast_ref::<crate::net::managed_socket::ManagedSocketError>()
                        .is_some_and(
                            crate::net::managed_socket::ManagedSocketError::is_fatal_topology_invariant,
                        )
                    {
                        return FailureClass::FatalInvariant;
                    }
                    current = error.source();
                }
                FailureClass::OperationFailed
            }
        }
    }

    pub(crate) fn is_fatal_topology_invariant(&self) -> bool {
        self.class().is_fatal()
    }
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::VersionExhausted { current } => {
                write!(formatter, "socket-manager version {current} is exhausted")
            }
            Self::VersionPublicationFailed { expected, actual } => match actual {
                Some(actual) => write!(
                    formatter,
                    "socket-manager version publication expected {expected}, observed {actual}"
                ),
                None => write!(
                    formatter,
                    "socket-manager version publication wrapped after prechecking {expected}"
                ),
            },
            Self::Reservation { operation, cause } => {
                write!(formatter, "{operation}: {cause}")
            }
            Self::FlowTopology { operation, cause } => {
                write!(formatter, "{operation}: {cause}")
            }
            Self::FlowAuthority { operation, cause } => {
                write!(formatter, "{operation}: {cause}")
            }
            Self::Poisoned { authority } => {
                write!(formatter, "{authority} authority lock is poisoned")
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
            Self::FlowTopology { cause, .. } => Some(cause),
            Self::FlowAuthority { cause, .. } => Some(cause),
            Self::VersionExhausted { .. }
            | Self::VersionPublicationFailed { .. }
            | Self::Reservation { .. }
            | Self::Poisoned { .. }
            | Self::TransactionFailed { .. } => None,
        }
    }
}

impl From<ReservationError> for ManagerError {
    fn from(cause: ReservationError) -> Self {
        Self::Reservation {
            operation: "validate client-flow reservation",
            cause,
        }
    }
}

impl From<crate::flow_state::FlowAuthorityError> for ManagerError {
    fn from(cause: crate::flow_state::FlowAuthorityError) -> Self {
        Self::FlowAuthority {
            operation: "publish client-flow authority",
            cause,
        }
    }
}
