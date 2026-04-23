use crate::cli::{IcmpReplyIdRequest, SupportedProtocol, TimeoutAction};
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::net::params::CanonicalAddr;
use pkthere_socket_policy::{ListenerWorkerSocketPolicy, ResolvedSocketPolicy, SocketEvidenceKey};
use socket2::{Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;

use super::state::{ListenerMetadata, UpstreamMetadata};

/// Snapshot of sockets and destination used by worker threads.
pub(crate) struct SocketHandles {
    pub listener: Arc<ListenerMetadata>,
    pub client_sock: Socket,
    pub upstream: Arc<UpstreamMetadata>,
    pub upstream_sock: Socket,
    pub version: u64,
}

impl SocketHandles {
    #[cfg(test)]
    pub(crate) fn new(
        listener: ListenerMetadata,
        client_sock: Socket,
        upstream: UpstreamMetadata,
        upstream_sock: Socket,
        version: u64,
    ) -> Self {
        Self {
            listener: Arc::new(listener),
            client_sock,
            upstream: Arc::new(upstream),
            upstream_sock,
            version,
        }
    }
}

pub(crate) struct SocketManagerInit {
    pub(crate) socket_slot: u32,
    pub(crate) client_sock: Socket,
    pub(crate) listen_local_filter: CanonicalAddr,
    pub(crate) listen_local_kernel_addr: SocketAddr,
    pub(crate) listen_sock_type: Type,
    pub(crate) listen_target: String,
    pub(crate) listen_proto: SupportedProtocol,
    pub(crate) listen_policy: ResolvedSocketPolicy,
    pub(crate) listen_worker_socket_policy: ListenerWorkerSocketPolicy,
    pub(crate) listen_debug_unconnected: bool,
    pub(crate) upstream_remote_filter: CanonicalAddr,
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
    pub listen_local_filter: CanonicalAddr,
    pub listen_local_kernel_addr: SocketAddr,
    pub listen_evidence_key: SocketEvidenceKey,
    pub listen_sock_type: Type,
    pub listen_policy: ResolvedSocketPolicy,
    pub upstream_remote_filter: CanonicalAddr,
    pub upstream_local_filter: CanonicalAddr,
    pub upstream_local_kernel_addr: SocketAddr,
    pub upstream_evidence_key: SocketEvidenceKey,
    pub upstream_flow: SocketLegFlow,
    pub upstream_connected: bool,
    pub upstream_proto: SupportedProtocol,
    pub upstream_sock_type: Type,
    pub upstream_policy: ResolvedSocketPolicy,
}
