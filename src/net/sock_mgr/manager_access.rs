use super::manager::lock_manager_authority;
use super::manager_types::SocketManager;
use crate::net::managed_socket::{ManagedReceiver, ManagedSocket};
use crate::net::sock_mgr::receiver_slot::{ReceiverClaim, ReceiverRole};
use crate::net::sock_mgr::{ManagerError, SocketHandles, SocketStateSnapshot, StateVersion};
use std::io;
use std::sync::Arc;

pub(crate) enum WorkerStateTransactionStart<'manager> {
    Current,
    Required(WorkerStateCapture<'manager>),
}

pub(crate) struct WorkerStateCapture<'manager> {
    manager: &'manager SocketManager,
}

impl WorkerStateCapture<'_> {
    pub(crate) fn capture(self) -> Result<SocketHandles, ManagerError> {
        self.manager.capture_handles_without_flow_read()
    }
}

impl SocketManager {
    pub(crate) fn claim_receiver(
        &self,
        role: ReceiverRole,
        worker_id: usize,
    ) -> io::Result<ReceiverClaim> {
        match role {
            ReceiverRole::Listener => self.listener_receiver.claim(worker_id),
            ReceiverRole::Upstream => self.upstream_receiver.claim(worker_id),
        }
    }

    pub(crate) fn try_receiver_generation(&self, role: ReceiverRole) -> Result<u64, ManagerError> {
        match role {
            ReceiverRole::Listener => self.listener_receiver.generation(),
            ReceiverRole::Upstream => self.upstream_receiver.generation(),
        }
        .map_err(|error| ManagerError::io("read managed receiver generation", error))
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn receiver_generation(&self, role: ReceiverRole) -> u64 {
        self.try_receiver_generation(role)
            .expect("read managed receiver generation in test")
    }

    pub(super) fn publish_receiver_socket(
        &self,
        role: ReceiverRole,
        socket: &ManagedSocket,
    ) -> Result<(), ManagerError> {
        let registry = match role {
            ReceiverRole::Listener => &self.listener_receiver,
            ReceiverRole::Upstream => &self.upstream_receiver,
        };
        registry
            .publish_socket(socket)
            .map(|_| ())
            .map_err(|error| ManagerError::io("publish managed receiver", error))
    }

    pub(super) fn publish_staged_receiver(
        &self,
        role: ReceiverRole,
        socket: &ManagedSocket,
        receiver: ManagedReceiver,
    ) -> Result<(), ManagerError> {
        let registry = match role {
            ReceiverRole::Listener => &self.listener_receiver,
            ReceiverRole::Upstream => &self.upstream_receiver,
        };
        registry
            .publish_staged(socket, receiver)
            .map(|_| ())
            .map_err(|error| ManagerError::io("publish staged managed receiver", error))
    }

    pub(super) fn precheck_receiver_publication(
        &self,
        role: ReceiverRole,
    ) -> Result<(), ManagerError> {
        let registry = match role {
            ReceiverRole::Listener => &self.listener_receiver,
            ReceiverRole::Upstream => &self.upstream_receiver,
        };
        registry
            .precheck_publication()
            .map_err(|error| ManagerError::io("precheck managed receiver publication", error))
    }

    #[inline]
    pub(crate) fn try_snapshot_state(&self) -> Result<SocketStateSnapshot, ManagerError> {
        let transaction = self.lock_transaction()?;
        let snapshot = self.snapshot_state_under_transaction()?;
        transaction
            .rollback()
            .map_err(|cause| ManagerError::Reservation {
                operation: "release manager snapshot transaction",
                cause,
            })?;
        Ok(snapshot)
    }

    fn snapshot_state_under_transaction(&self) -> Result<SocketStateSnapshot, ManagerError> {
        let listener = lock_manager_authority(&self.client_listen, "listener manager")?;
        let upstream = lock_manager_authority(&self.upstream_state, "upstream manager")?;
        Ok(SocketStateSnapshot {
            version: self.version.current(),
            locked_flow: listener.flow,
            listener_flow: listener.listener_flow,
            listener_connected: listener.sock.is_connected(),
            client_proto: self.listen_proto,
            listen_local_filter: listener.listen_local_filter,
            listen_evidence_key: listener.evidence_key,
            listen_sock_type: listener.sock_type,
            listen_policy: listener.policy,
            upstream_remote_filter: upstream.upstream_remote_filter,
            upstream_local_filter: upstream.upstream_local_filter,
            upstream_evidence_key: upstream.evidence_key,
            upstream_flow: upstream.upstream_flow,
            upstream_connected: upstream.sock.is_connected(),
            upstream_proto: self.upstream_proto,
            upstream_sock_type: upstream.sock_type,
            upstream_policy: upstream.policy,
        })
    }

    #[inline]
    pub(super) fn capture_handles_without_flow_read(&self) -> Result<SocketHandles, ManagerError> {
        let transaction = self.lock_transaction()?;
        let handles = self.snapshot_handles_under_transaction()?;
        transaction
            .rollback()
            .map_err(|cause| ManagerError::Reservation {
                operation: "release manager handle transaction",
                cause,
            })?;
        Ok(handles)
    }

    pub(crate) fn capture_startup_handles(&self) -> Result<SocketHandles, ManagerError> {
        self.capture_handles_without_flow_read()
    }

    /// Begins the sole worker-state reconciliation protocol. A caller cannot
    /// capture manager resources unless the atomic publication check produced
    /// the consuming token returned by `Required`.
    pub(crate) fn begin_worker_state_transaction(
        &self,
        installed: StateVersion,
    ) -> WorkerStateTransactionStart<'_> {
        if self.version.current() == installed {
            WorkerStateTransactionStart::Current
        } else {
            WorkerStateTransactionStart::Required(WorkerStateCapture { manager: self })
        }
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn snapshot_state(&self) -> SocketStateSnapshot {
        self.try_snapshot_state().expect("manager snapshot")
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn test_handle_snapshot(&self) -> SocketHandles {
        self.capture_handles_without_flow_read()
            .expect("manager snapshot")
    }

    fn snapshot_handles_under_transaction(&self) -> Result<SocketHandles, ManagerError> {
        let listener = lock_manager_authority(&self.client_listen, "listener manager")?;
        let upstream = lock_manager_authority(&self.upstream_state, "upstream manager")?;
        Ok(SocketHandles {
            listener: Arc::clone(&listener.metadata),
            client_sock: listener.sock.clone(),
            upstream: Arc::clone(&upstream.metadata),
            upstream_sock: upstream.sock.clone(),
            version: self.version.current(),
        })
    }
}
