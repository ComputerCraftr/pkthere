use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::net::managed_socket::ManagedSocket;
use crate::net::packet_headers::ReceiveParserKernel;
use crate::net::socket::family_changed;
use pkthere_socket_policy::{ResolvedSocketPolicy, SocketEvidenceKey};
use socket2::Type;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct ListenerMetadata {
    pub(crate) listen_local_filter: LogicalEndpoint,
    pub(crate) listen_local_kernel_addr: SocketAddr,
    pub(crate) evidence_key: SocketEvidenceKey,
    pub(crate) flow: Option<ClientFlowKey>,
    pub(crate) listener_flow: SocketLegFlow,
    pub(crate) sock_type: Type,
    pub(crate) policy: ResolvedSocketPolicy,
    pub(crate) parser: ReceiveParserKernel,
}

#[derive(Clone)]
pub(crate) struct UpstreamMetadata {
    pub(crate) upstream_remote_filter: LogicalEndpoint,
    pub(crate) upstream_local_filter: LogicalEndpoint,
    pub(crate) upstream_local_kernel_addr: SocketAddr,
    pub(crate) evidence_key: SocketEvidenceKey,
    pub(crate) upstream_flow: SocketLegFlow,
    pub(crate) sock_type: Type,
    pub(crate) policy: ResolvedSocketPolicy,
    pub(crate) parser: ReceiveParserKernel,
}

pub(super) struct ClientListenState {
    pub(super) sock: ManagedSocket,
    pub(super) metadata: Arc<ListenerMetadata>,
}

impl Deref for ClientListenState {
    type Target = ListenerMetadata;

    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

impl DerefMut for ClientListenState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.metadata)
    }
}

pub(super) struct UpstreamState {
    pub(super) sock: ManagedSocket,
    pub(super) metadata: Arc<UpstreamMetadata>,
}

impl Deref for UpstreamState {
    type Target = UpstreamMetadata;

    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

impl DerefMut for UpstreamState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.metadata)
    }
}

pub(super) struct ReresolveResult<M> {
    pub(super) sock: ManagedSocket,
    pub(super) metadata: Arc<M>,
    pub(super) update: SocketUpdateKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketUpdateKind {
    Unchanged,
    MetadataUpdated,
    ReconnectedInPlace,
    Replaced,
    ReplacedCrossFamily,
}

impl SocketUpdateKind {
    #[inline]
    pub(crate) const fn changed(self) -> bool {
        !matches!(self, Self::Unchanged)
    }

    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::MetadataUpdated => "metadata-updated",
            Self::ReconnectedInPlace => "reconnected-in-place",
            Self::Replaced => "replaced",
            Self::ReplacedCrossFamily => "replaced-cross-family",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReresolveAction {
    NoChange,
    UpdateMetadataOnly,
    ReconnectInPlace,
    ReplaceSocket,
}

#[inline]
pub(super) fn decide_listener_reresolve(
    prev: LogicalEndpoint,
    resolved: SocketAddr,
) -> (LogicalEndpoint, ReresolveAction) {
    decide_listener_endpoint_update(prev, prev.with_resolved_ip(resolved))
}

#[inline]
pub(super) fn decide_listener_endpoint_update(
    prev: LogicalEndpoint,
    fresh: LogicalEndpoint,
) -> (LogicalEndpoint, ReresolveAction) {
    if fresh == prev {
        (prev, ReresolveAction::NoChange)
    } else {
        (fresh, ReresolveAction::ReplaceSocket)
    }
}

#[inline]
pub(super) fn decide_upstream_reresolve(
    prev: LogicalEndpoint,
    resolved: SocketAddr,
    upstream_connected: bool,
    policy: ResolvedSocketPolicy,
) -> (LogicalEndpoint, ReresolveAction) {
    decide_upstream_endpoint_update(
        prev,
        prev.with_resolved_ip(resolved),
        upstream_connected,
        policy,
    )
}

#[inline]
pub(super) fn decide_upstream_endpoint_update(
    prev: LogicalEndpoint,
    fresh: LogicalEndpoint,
    upstream_connected: bool,
    policy: ResolvedSocketPolicy,
) -> (LogicalEndpoint, ReresolveAction) {
    if fresh == prev {
        return (prev, ReresolveAction::NoChange);
    }
    if family_changed(prev.to_socket_addr(), fresh.to_socket_addr()) {
        return (fresh, ReresolveAction::ReplaceSocket);
    }

    if !upstream_connected {
        if matches!(
            policy.reuse.reresolve_mode,
            pkthere_socket_policy::SocketReresolveMode::MetadataOnlyWhenUnconnected
        ) {
            (fresh, ReresolveAction::UpdateMetadataOnly)
        } else {
            (fresh, ReresolveAction::ReplaceSocket)
        }
    } else if policy.reuse.reconnects_in_place() {
        (fresh, ReresolveAction::ReconnectInPlace)
    } else {
        (fresh, ReresolveAction::ReplaceSocket)
    }
}
