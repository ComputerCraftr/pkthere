//! Versioned listener and upstream socket management.

mod debug_resolver;
mod error;
mod fifo_core;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod fifo_core_loom;
mod group_publication;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod group_publication_loom;
mod handles;
mod manager;
mod manager_access;
mod manager_client_flow;
mod manager_init;
mod manager_listener_replacement;
mod manager_reresolve;
mod manager_reresolve_apply;
mod manager_types;
mod manager_version_access;
mod receiver_slot;
mod receiver_transfer;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod receiver_transfer_loom;
mod state;
pub(crate) mod transaction_lock;
mod version;

pub(crate) use debug_resolver::{
    DebugAddressResolver, DebugAddressRevision, DebugResolverDecision,
};
pub(crate) use error::{ManagerError, RecoveryOutcome, TransactionJournalEntry, TransactionLeg};
pub(crate) use handles::{
    ClearedClientFlow, PublishedUpdate, SharedUpstreamIdentity, SocketHandles, SocketManagerInit,
    SocketStateSnapshot,
};
pub(crate) use manager::socket_evidence_key_json;
pub(crate) use manager_access::WorkerStateTransactionStart;
pub(crate) use manager_reresolve::PreparedReresolveGroup;
pub(crate) use manager_types::{
    ClientFlowUpdate, PreparedClientFlowGroup, ReresolveSummary, SocketManager,
};
pub(crate) use pkthere_socket_policy::SocketEvidenceKey;
#[cfg(all(test, not(miri)))]
pub(crate) use receiver_slot::ReceiverRegistry;
pub(crate) use receiver_slot::{ReceiverClaim, ReceiverRole};
#[cfg(all(test, not(miri)))]
pub(crate) use state::{ListenerMetadata, UpstreamMetadata};
pub(crate) use version::StateVersion;

#[cfg(test)]
mod debug_resolver_unit_tests;
#[cfg(test)]
mod error_unit_tests;
#[cfg(all(test, not(miri)))]
mod receiver_slot_unit_tests;
#[cfg(all(test, not(miri)))]
mod tests;
#[cfg(all(test, not(miri)))]
mod transaction_failure_tests;
#[cfg(test)]
mod transaction_lock_unit_tests;
#[cfg(all(test, not(miri)))]
mod transaction_tests;
#[cfg(test)]
mod version_core_tests;
