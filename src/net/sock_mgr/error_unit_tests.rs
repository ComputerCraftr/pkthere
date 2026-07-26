use super::ManagerError;
use crate::net::managed_socket::{AssociationOperation, ManagedSocketError};
use crate::net::sock_mgr::StateVersion;
use crate::net::sock_mgr::transaction_lock::ReservationError;
use crate::runtime_support::FailureClass;
use std::io;

#[test]
fn topology_quiescence_failure_remains_typed_through_manager_context() {
    let error = ManagerError::io(
        "reserve topology",
        io::Error::other(ManagedSocketError::TopologyQuiescenceLost {
            operation: AssociationOperation::Replace,
            active_io: 1,
            epoch: 7,
        }),
    );
    assert!(error.is_fatal_topology_invariant());
}

#[test]
fn ordinary_resolution_error_remains_retryable() {
    let error = ManagerError::io(
        "resolve upstream",
        io::Error::new(io::ErrorKind::AddrNotAvailable, "unavailable"),
    );
    assert!(!error.is_fatal_topology_invariant());
}

#[test]
fn every_manager_error_variant_has_an_explicit_failure_class() {
    assert_eq!(
        ManagerError::io(
            "resolve upstream",
            io::Error::new(io::ErrorKind::AddrNotAvailable, "unavailable"),
        )
        .class(),
        FailureClass::OperationFailed
    );
    assert_eq!(
        ManagerError::Reservation {
            operation: "reserve",
            cause: ReservationError::TimedOut,
        }
        .class(),
        FailureClass::RetryableContention
    );
    assert_eq!(
        ManagerError::Reservation {
            operation: "reserve",
            cause: ReservationError::Shutdown,
        }
        .class(),
        FailureClass::Shutdown
    );
    assert_eq!(
        ManagerError::Reservation {
            operation: "reserve",
            cause: ReservationError::OwnershipLost,
        }
        .class(),
        FailureClass::FatalInvariant
    );
    assert_eq!(
        ManagerError::FlowTopology {
            operation: "read",
            cause: crate::flow_state::FlowTopologyError::Busy,
        }
        .class(),
        FailureClass::RetryableContention
    );
    assert_eq!(
        ManagerError::FlowTopology {
            operation: "read",
            cause: crate::flow_state::FlowTopologyError::Poisoned,
        }
        .class(),
        FailureClass::FatalInvariant
    );
    assert_eq!(
        ManagerError::FlowAuthority {
            operation: "publish",
            cause: crate::flow_state::FlowAuthorityError::Reservation(
                ReservationError::OwnershipLost,
            ),
        }
        .class(),
        FailureClass::FatalInvariant
    );
    for error in [
        ManagerError::VersionExhausted {
            current: StateVersion::INITIAL,
        },
        ManagerError::VersionPublicationFailed {
            expected: StateVersion::INITIAL,
            actual: None,
        },
        ManagerError::Poisoned { authority: "test" },
        ManagerError::TransactionFailed {
            operation: "test",
            cause: "injected".to_owned(),
            journal: Vec::new(),
        },
    ] {
        assert_eq!(error.class(), FailureClass::FatalInvariant);
    }
}
