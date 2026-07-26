use super::transport::SocketLeg;
use crate::cli::{ListenMode, RuntimeConfig, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::flow_state::{FlowAdmissionSnapshot, PendingIcmpClientLock, SessionAdmissionSnapshot};
use crate::net::framing_shim::SessionId;
use crate::net::packet_headers::ReceiveParserKernel;
use crate::net::sock_mgr::SocketHandles;
use pkthere_socket_policy::{ReceiveEvidencePolicy, ResolvedSocketPolicy};
use socket2::Type;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReceiveSocketContext {
    pub(crate) role: SocketLeg,
    pub(crate) proto: SupportedProtocol,
    pub(crate) sock_type: Type,
    pub(crate) parser: ReceiveParserKernel,
    pub(crate) policy: ResolvedSocketPolicy,
    pub(crate) connected: bool,
    pub(crate) local_filter: LogicalEndpoint,
    pub(crate) local_kernel_addr: SocketAddr,
    pub(crate) evidence_key: pkthere_socket_policy::SocketEvidenceKey,
}

impl ReceiveSocketContext {
    pub(crate) fn evidence_policy(self) -> ReceiveEvidencePolicy {
        self.policy.evidence_policy(self.connected)
    }

    pub(crate) const fn socket_is_ipv4(self) -> bool {
        matches!(
            self.parser.version(),
            crate::net::packet_headers::IpVersion::V4
        )
    }

    #[inline]
    pub(crate) fn can_honor_disjoint_icmp_ids(self) -> bool {
        self.policy
            .icmp
            .is_some_and(|policy| policy.can_honor_disjoint_ids())
    }

    #[inline]
    pub(crate) fn allow_debug_kernel_echo_self_handshake(self) -> bool {
        self.policy
            .icmp
            .is_some_and(|policy| policy.allow_debug_kernel_echo_self_handshake)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionStateContext<'snapshot> {
    pub(crate) expected_inbound: Option<FlowTuple>,
    pub(crate) expected_local: Option<LogicalEndpoint>,
    pub(crate) locked_flow: Option<ClientFlowKey>,
    pub(crate) pending_icmp_client_lock: Option<PendingIcmpClientLock>,
    pub(crate) expected_session_id: Option<SessionId>,
    pub(crate) additional_sessions: &'snapshot SessionAdmissionSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReceiveContext<'snapshot> {
    pub(crate) socket: ReceiveSocketContext,
    pub(crate) admission: AdmissionStateContext<'snapshot>,
}

impl ReceiveContext<'_> {
    #[inline]
    pub(crate) const fn local_filter(self) -> Option<LogicalEndpoint> {
        Some(self.socket.local_filter)
    }

    #[inline]
    pub(crate) fn expected_remote(self) -> Option<LogicalEndpoint> {
        self.admission.expected_inbound.map(|flow| flow.src)
    }

    #[inline]
    pub(crate) const fn expected_local_id(self) -> Option<u16> {
        match self.admission.expected_inbound {
            Some(flow) => Some(flow.dst.id()),
            None => match self.admission.expected_local {
                Some(endpoint) => Some(endpoint.id()),
                None => None,
            },
        }
    }
}

#[inline]
pub(crate) fn upstream_receive_context<'snapshot>(
    _cfg: &RuntimeConfig,
    handles: &SocketHandles,
    flow: &'snapshot FlowAdmissionSnapshot,
) -> ReceiveContext<'snapshot> {
    let parser_protocol = handles.upstream.parser.protocol();
    let flow_matches_handles = flow.locked && flow.client_flow == handles.listener.flow;
    ReceiveContext {
        socket: ReceiveSocketContext {
            role: SocketLeg::UpstreamFacing,
            proto: parser_protocol,
            sock_type: handles.upstream.sock_type,
            parser: handles.upstream.parser,
            policy: handles.upstream.policy,
            connected: handles.upstream_connected(),
            local_filter: handles.upstream.upstream_local_filter,
            local_kernel_addr: handles.upstream.upstream_local_kernel_addr,
            evidence_key: handles.upstream.evidence_key,
        },
        admission: AdmissionStateContext {
            expected_inbound: flow_matches_handles
                .then_some(handles.upstream.upstream_flow.inbound)
                .flatten(),
            expected_local: flow_matches_handles
                .then_some(handles.upstream.upstream_flow.inbound)
                .flatten()
                .map(|flow| flow.dst),
            locked_flow: flow_matches_handles.then_some(flow.client_flow).flatten(),
            pending_icmp_client_lock: None,
            expected_session_id: flow.upstream_receive_session_id,
            additional_sessions: &flow.upstream_sessions,
        },
    }
}

#[inline]
pub(crate) fn client_receive_context<'snapshot>(
    cfg: &RuntimeConfig,
    handles: &SocketHandles,
    flow: &'snapshot FlowAdmissionSnapshot,
) -> ReceiveContext<'snapshot> {
    let parser_protocol = handles.listener.parser.protocol();
    let flow_matches_handles = flow.locked && flow.client_flow == handles.listener.flow;
    let expected_inbound = flow_matches_handles
        .then_some(handles.listener.listener_flow.inbound)
        .flatten();
    let expected_local = if parser_protocol == SupportedProtocol::ICMP {
        match (cfg.listen_mode, expected_inbound) {
            (ListenMode::Fixed, _) => Some(
                handles
                    .listener
                    .listen_local_filter
                    .with_id(cfg.listen.id()),
            ),
            (ListenMode::Dynamic, Some(flow)) => Some(flow.dst),
            (ListenMode::Dynamic, None) => None,
        }
    } else {
        None
    };

    ReceiveContext {
        socket: ReceiveSocketContext {
            role: SocketLeg::ClientFacing,
            proto: parser_protocol,
            sock_type: handles.listener.sock_type,
            parser: handles.listener.parser,
            policy: handles.listener.policy,
            connected: handles.listener_connected(),
            local_filter: handles.listener.listen_local_filter,
            local_kernel_addr: handles.listener.listen_local_kernel_addr,
            evidence_key: handles.listener.evidence_key,
        },
        admission: AdmissionStateContext {
            expected_inbound,
            expected_local,
            locked_flow: flow_matches_handles.then_some(flow.client_flow).flatten(),
            pending_icmp_client_lock: flow.pending_icmp_client_lock,
            expected_session_id: flow.client_receive_session_id,
            additional_sessions: &flow.client_sessions,
        },
    }
}
