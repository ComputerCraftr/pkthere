#[cfg(any(test, feature = "authority-audit"))]
use super::OperationId;
use super::{AuthorityId, WaitId};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AuthorityInstance {
    pub(crate) id: AuthorityId,
    pub(crate) flow: u64,
    pub(crate) direction: u8,
    pub(crate) kind: u8,
    pub(crate) session: u64,
}

impl AuthorityInstance {
    pub(crate) const fn singleton(id: AuthorityId) -> Self {
        Self {
            id,
            flow: 0,
            direction: 0,
            kind: 0,
            session: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityError {
    Poisoned(AuthorityId),
    #[cfg(any(test, feature = "authority-audit"))]
    AuditViolation,
    #[cfg(any(test, feature = "authority-audit"))]
    OperationConflict {
        operation: OperationId,
        held: AuthorityId,
    },
    #[cfg(any(test, feature = "authority-audit"))]
    MissingOperationAuthority {
        operation: OperationId,
        required: AuthorityId,
    },
    #[cfg(any(test, feature = "authority-audit"))]
    AcquisitionConflict {
        held: AuthorityInstance,
        held_at: u32,
        requested: AuthorityInstance,
        requested_at: u32,
    },
    #[cfg(any(test, feature = "authority-audit"))]
    OperationAcquisitionConflict {
        operation: OperationId,
        requested: AuthorityId,
    },
    #[cfg(any(test, feature = "authority-audit"))]
    MissingWaitContract {
        wait: WaitId,
    },
    #[cfg(any(test, feature = "authority-audit"))]
    MissingRetainedWaitAuthority {
        wait: WaitId,
        required: AuthorityId,
    },
    WaitGuardOwnershipLost {
        wait: WaitId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityTryLockError {
    WouldBlock,
    Authority(AuthorityError),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(any(test, feature = "authority-audit"))]
        if let Self::AcquisitionConflict {
            held,
            held_at,
            requested,
            requested_at,
        } = self
        {
            return write!(
                formatter,
                "authority conflict held={:?}@{} requested={:?}@{}",
                held.id, held_at, requested.id, requested_at
            );
        }
        crate::runtime_support::format_debug(self, formatter)
    }
}

impl std::error::Error for AuthorityError {}
