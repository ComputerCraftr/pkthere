use crate::cli::{IcmpReplyIdRequest, SupportedProtocol, TimeoutAction};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::net::managed_socket::ManagedSocket;
use pkthere_socket_policy::{ListenerWorkerSocketPolicy, ResolvedSocketPolicy, SocketEvidenceKey};
use socket2::Type;
use std::net::SocketAddr;
use std::sync::Arc;

use super::state::{ListenerMetadata, UpstreamMetadata};

/// Snapshot of sockets and destination used by worker threads.
pub(crate) struct SocketHandles {
    pub listener: Arc<ListenerMetadata>,
    pub client_sock: ManagedSocket,
    pub upstream: Arc<UpstreamMetadata>,
    pub upstream_sock: ManagedSocket,
    pub version: u64,
}

impl SocketHandles {
    #[inline]
    pub(crate) fn listener_connected(&self) -> bool {
        self.client_sock.is_connected()
    }

    #[inline]
    pub(crate) fn upstream_connected(&self) -> bool {
        self.upstream_sock.is_connected()
    }

    #[cfg(test)]
    pub(crate) fn new(
        listener: ListenerMetadata,
        client_sock: impl Into<ManagedSocket>,
        upstream: UpstreamMetadata,
        upstream_sock: impl Into<ManagedSocket>,
        version: u64,
    ) -> Self {
        Self {
            listener: Arc::new(listener),
            client_sock: client_sock.into(),
            upstream: Arc::new(upstream),
            upstream_sock: upstream_sock.into(),
            version,
        }
    }
}

pub(crate) struct SocketManagerInit {
    pub(crate) socket_slot: u32,
    pub(crate) client_sock: ManagedSocket,
    pub(crate) listen_local_filter: LogicalEndpoint,
    pub(crate) listen_local_kernel_addr: SocketAddr,
    pub(crate) listen_sock_type: Type,
    pub(crate) listen_target: String,
    pub(crate) listen_proto: SupportedProtocol,
    pub(crate) listen_policy: ResolvedSocketPolicy,
    pub(crate) listen_worker_socket_policy: ListenerWorkerSocketPolicy,
    pub(crate) listen_debug_unconnected: bool,
    pub(crate) upstream_remote_filter: LogicalEndpoint,
    pub(crate) upstream_target: String,
    pub(crate) upstream_source_id_request: IcmpReplyIdRequest,
    pub(crate) upstream_reply_id_request: IcmpReplyIdRequest,
    pub(crate) upstream_proto: SupportedProtocol,
    pub(crate) upstream_debug_unconnected: bool,
    pub(crate) upstream_icmp_kernel_echo_self_handshake: bool,
    pub(crate) force_raw_icmp_wildcard_upstream: bool,
    pub(crate) timeout_act: TimeoutAction,
    pub(crate) debug_handles: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct SocketStateSnapshot {
    pub locked_flow: Option<ClientFlowKey>,
    pub listener_flow: SocketLegFlow,
    pub listener_connected: bool,
    pub client_proto: SupportedProtocol,
    pub listen_local_filter: LogicalEndpoint,
    pub listen_local_kernel_addr: SocketAddr,
    pub listen_evidence_key: SocketEvidenceKey,
    pub listen_sock_type: Type,
    pub listen_policy: ResolvedSocketPolicy,
    pub upstream_remote_filter: LogicalEndpoint,
    pub upstream_local_filter: LogicalEndpoint,
    pub upstream_local_kernel_addr: SocketAddr,
    pub upstream_evidence_key: SocketEvidenceKey,
    pub upstream_flow: SocketLegFlow,
    pub upstream_connected: bool,
    pub upstream_proto: SupportedProtocol,
    pub upstream_sock_type: Type,
    pub upstream_policy: ResolvedSocketPolicy,
}
