use pkthere_socket_policy::ListenerWorkerSocketPolicy;

use super::manager_types::SocketManager;
use super::transaction_lock::ManagerTransactionGuard;
use crate::net::sock_mgr::version::VersionCapacityGuard;
use crate::net::sock_mgr::{ManagerError, StateVersion};
use std::time::Instant;

use crate::net::sock_mgr::transaction_lock::MANAGER_RESERVATION_TIMEOUT;

impl SocketManager {
    #[inline]
    pub const fn get_listener_worker_socket_policy(&self) -> ListenerWorkerSocketPolicy {
        self.listen_worker_socket_policy
    }

    #[inline]
    pub(crate) const fn socket_slot(&self) -> u32 {
        self.socket_slot
    }

    #[inline]
    #[track_caller]
    pub(super) fn lock_transaction(&self) -> Result<ManagerTransactionGuard<'_>, ManagerError> {
        self.lock_transaction_until(Instant::now() + MANAGER_RESERVATION_TIMEOUT)
    }

    #[inline]
    #[track_caller]
    pub(super) fn lock_transaction_until(
        &self,
        deadline: Instant,
    ) -> Result<ManagerTransactionGuard<'_>, ManagerError> {
        self.transaction
            .reserve_until(deadline)
            .map_err(|error| ManagerError::Reservation {
                operation: "reserve socket-manager transaction",
                cause: error,
            })
    }

    #[inline]
    pub(super) fn precheck_version_capacity(
        &self,
        _transaction: &ManagerTransactionGuard<'_>,
    ) -> Result<VersionCapacityGuard, ManagerError> {
        self.version.precheck_capacity()
    }

    #[inline]
    pub(super) fn publish_prechecked(
        &self,
        _transaction: &ManagerTransactionGuard<'_>,
        capacity: VersionCapacityGuard,
    ) -> Result<StateVersion, ManagerError> {
        self.version.publish_prechecked(capacity)
    }
}
