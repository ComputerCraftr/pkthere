use super::receiver_slot::ReceiverRegistry;
use super::state::{ClientListenState, ListenerMetadata, SocketUpdateKind, UpstreamState};
use super::transaction_lock::{
    ManagerTransaction, ManagerTransactionGuard, ManagerTransactionGuardSet,
};
use super::version::{VersionCapacityGuard, VersionClock};
use super::{PublishedUpdate, SocketEvidenceKey, SocketHandles, TransactionJournalEntry};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol, TimeoutAction};
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::net::managed_socket::TopologyReservation;
use pkthere_socket_policy::{ListenerWorkerSocketPolicy, UpstreamWorkerSocketPolicy};
use std::net::SocketAddr;
use std::sync::Arc;

pub(crate) struct ReresolveSummary {
    pub(crate) socket_slot: u32,
    pub(crate) handles: SocketHandles,
    pub(crate) listener_update: SocketUpdateKind,
    pub(crate) upstream_update: SocketUpdateKind,
    pub(crate) old_listener_key: SocketEvidenceKey,
    pub(crate) new_listener_key: SocketEvidenceKey,
    pub(crate) old_upstream_key: SocketEvidenceKey,
    pub(crate) new_upstream_key: SocketEvidenceKey,
}

#[derive(Clone, Copy)]
pub(crate) struct ClientFlowUpdate {
    pub(crate) flow: ClientFlowKey,
    pub(crate) listener_flow: SocketLegFlow,
    /// Socket that admitted the flow. The manager's resolved listener
    /// lifecycle—not the caller—decides whether this slot becomes the sole
    /// connected owner.
    pub(crate) admitting_listener_slot: u32,
    pub(crate) client: SocketAddr,
}

impl ReresolveSummary {
    pub(crate) const fn listener_replaced(&self) -> bool {
        matches!(
            self.listener_update,
            SocketUpdateKind::Replaced | SocketUpdateKind::ReplacedCrossFamily
        )
    }
}

/// Manages both listener and upstream sockets and publishes versioned updates.
///
/// **STRICT LOCK ORDER**:
/// 1. global client-flow transaction, when applicable
/// 2. manager transactions sorted by `socket_slot`
/// 3. `client_listen`
/// 4. `upstream`
/// 5. a selected `ManagedSocket` transition mutex
pub(crate) struct SocketManager {
    pub(super) transaction: ManagerTransaction,
    pub(super) socket_slot: u32,
    pub(super) worker_io_lanes: usize,
    pub(super) client_listen:
        crate::authority::AuthorityMutex<crate::authority::tags::ManagerState, ClientListenState>,
    pub(super) listener_receiver: Arc<ReceiverRegistry>,
    pub(super) listen_target: String,
    pub(super) listen_proto: SupportedProtocol,
    pub(super) listen_debug_unconnected: bool,
    pub(super) listen_worker_socket_policy: ListenerWorkerSocketPolicy,
    pub(super) upstream_state:
        crate::authority::AuthorityMutex<crate::authority::tags::ManagerState, UpstreamState>,
    pub(super) upstream_receiver: Arc<ReceiverRegistry>,
    pub(super) upstream_target: String,
    pub(super) upstream_source_id_request: IcmpReplyIdRequest,
    pub(super) upstream_reply_id_request: IcmpReplyIdRequest,
    pub(super) upstream_proto: SupportedProtocol,
    pub(super) upstream_debug_unconnected: bool,
    pub(super) upstream_icmp_kernel_echo_self_handshake: bool,
    pub(super) upstream_worker_socket_policy: UpstreamWorkerSocketPolicy,
    pub(super) force_raw_icmp_wildcard_upstream: bool,
    pub(super) debug_handles: bool,
    pub(super) timeout_action: TimeoutAction,
    pub(super) version: VersionClock,
}

pub(crate) struct PreparedClientFlowGroup<'a> {
    pub(super) ordered: Vec<&'a SocketManager>,
    pub(super) update: ClientFlowUpdate,
    pub(super) versions: Vec<super::StateVersion>,
    pub(super) listener_states: Vec<ClientListenState>,
    pub(super) upstream_states: Vec<UpstreamState>,
    pub(super) listener_associations: Vec<crate::net::managed_socket::AssociationState>,
    pub(super) published_listener_metadata: Vec<Arc<ListenerMetadata>>,
    pub(super) transaction_guard_storage: Vec<ManagerTransactionGuard<'a>>,
    pub(super) listener_guard_storage: Vec<
        crate::authority::AuthorityMutexGuard<
            'a,
            crate::authority::tags::ManagerState,
            ClientListenState,
        >,
    >,
    pub(super) upstream_guard_storage: Vec<
        crate::authority::AuthorityMutexGuard<
            'a,
            crate::authority::tags::ManagerState,
            UpstreamState,
        >,
    >,
    pub(super) capacities: Vec<Option<VersionCapacityGuard>>,
    pub(super) transition_phases: Vec<ClientFlowSocketTransitionPhase>,
    pub(super) journal: Vec<TransactionJournalEntry>,
    pub(super) topology: Vec<Option<TopologyReservation>>,
    pub(super) published: Vec<PublishedUpdate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClientFlowSocketTransitionPhase {
    Reserved,
    Attempted,
    Completed,
}

pub(crate) struct PreparedClientFlowTransition<'manager, 'reservation, 'flow> {
    pub(super) prepared: PreparedClientFlowGroup<'manager>,
    pub(super) visibility: crate::flow_state::ClientFlowTopologyReservation<'reservation, 'flow>,
    pub(super) transaction_guards: ManagerTransactionGuardSet<'manager>,
}
