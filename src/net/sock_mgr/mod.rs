//! Versioned listener and upstream socket management.

mod debug_resolver;
mod error;
mod evidence;
mod flow;
mod handles;
mod manager;
mod state;
mod version;

pub(crate) use debug_resolver::{
    DebugAddressResolver, DebugAddressRevision, DebugResolverDecision,
};
pub(crate) use error::{ManagerError, RecoveryOutcome, TransactionJournalEntry, TransactionLeg};
pub(crate) use evidence::socket_evidence_key_json;
pub(crate) use handles::{
    ClearedClientFlow, PublishedUpdate, SocketHandles, SocketManagerInit, SocketStateSnapshot,
};
pub(crate) use manager::{ClientFlowUpdate, ReresolveSummary, SocketManager};
pub(crate) use pkthere_socket_policy::SocketEvidenceKey;
#[cfg(all(test, not(miri)))]
pub(crate) use state::{ListenerMetadata, UpstreamMetadata};
pub(crate) use version::StateVersion;

#[cfg(all(test, not(miri)))]
mod tests;
