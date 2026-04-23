//! Versioned listener and upstream socket management.

mod debug_resolver;
mod evidence;
mod flow;
mod handles;
mod manager;
mod state;

pub(crate) use debug_resolver::{
    DebugAddressResolver, DebugAddressRevision, DebugResolverDecision,
};
pub(crate) use evidence::socket_evidence_key_json;
pub(crate) use handles::{SocketHandles, SocketManagerInit, SocketStateSnapshot};
pub(crate) use manager::{ReresolveSummary, SocketManager};
pub(crate) use pkthere_socket_policy::SocketEvidenceKey;
#[cfg(test)]
pub(crate) use state::{ListenerMetadata, UpstreamMetadata};

#[cfg(test)]
mod tests;
