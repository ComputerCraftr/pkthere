//! Synchronization and ownership authority catalog.
//!
const EMERGENCY_KIND_MASK: u64 = u8::MAX as u64;
const EMERGENCY_EXPECTED_SHIFT: u32 = 8;
const EMERGENCY_OBSERVED_SHIFT: u32 = 16;
const EMERGENCY_EXPECTED_INSTANCE_SHIFT: u32 = 24;
const EMERGENCY_OBSERVED_INSTANCE_SHIFT: u32 = 40;
const EMERGENCY_INSTANCE_MASK: u64 = u16::MAX as u64;
const EMERGENCY_MISSING_ORDINAL: u64 = u8::MAX as u64;

mod catalog;
pub(crate) use catalog::{
    ATOMIC_PROTOCOL_RECORDS, AUTHORITY_RECORDS, BLOCKING_CONTRACTS, BLOCKING_EDGES, COHOLD_RULES,
    LIFECYCLE_OWNERSHIP_RECORDS, NEGATIVE_CONTROL_EXPECTATIONS, OPERATION_RECORDS,
    OPERATION_REQUIREMENTS, PUBLICATION_RECORDS, REFERENCE_COUNT_OWNERSHIP_RECORDS,
    SHARED_RMW_RECORDS, WAIT_PROTOCOL_RECORDS, WAIT_RECORDS,
};
mod error;
pub(crate) use error::{AuthorityError, AuthorityInstance, AuthorityTryLockError};
mod catalog_validation;
mod scopes;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod single_consumer_loom;
mod synchronization;
mod thread_owned;
mod validation;
mod wait_core;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod wait_core_loom;
mod worker_audit;
#[cfg(any(test, feature = "authority-audit"))]
mod worker_audit_core;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod worker_audit_core_loom;

pub(crate) use scopes::{
    AuditedOperationScope, AuthorityChannelReceiver, AuthorityChannelSender, AuthorityQueue,
    AuthorityScope, SingleConsumerBootstrap, bounded_authority_channel,
};
pub(crate) use synchronization::{
    AuthorityAtomic, AuthorityCondvar, AuthorityMutex, AuthorityMutexGuard, AuthorityMutexGuardSet,
    AuthorityOnceLock, audited_operation, audited_thread_sleep,
};
pub(crate) use thread_owned::ThreadOwned;
#[cfg(test)]
pub(crate) use validation::{
    acquisition_count_for_test, allocation_violation_count_for_authority_for_test,
    allocation_violation_count_for_test, is_held_for_test, operation_count_for_test,
    shared_rmw_count_for_test, wait_count_for_test,
};
pub(crate) use validation::{
    emergency_failure_code, emergency_failure_report, emergency_failure_source, validate_catalog,
};
#[cfg(any(test, feature = "authority-audit"))]
pub(crate) use worker_audit::AuditThreadRecord;
pub(crate) use worker_audit::{AuditDirection, WorkerAuditIdentity, WorkerAuditRegistry};

#[cfg(any(test, feature = "authority-audit"))]
mod audit_enabled;
#[cfg(any(test, feature = "authority-audit"))]
use audit_enabled as audit;
#[cfg(not(any(test, feature = "authority-audit")))]
mod audit_disabled;
#[cfg(not(any(test, feature = "authority-audit")))]
use audit_disabled as audit;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum AuthorityId {
    FlowRead,
    FlowReservation,
    FlowClaim,
    FlowWrite,
    ManagerTransaction,
    ManagerState,
    SocketTopology,
    SocketAssociation,
    SocketDescriptor,
    SocketIo,
    ControlObservation,
    ProtocolTransmit,
    ProtocolReceive,
    ResetBudget,
    SessionControl,
    Activity,
    Maintenance,
    WakeGeneration,
    ReceiverClaim,
    WaitCoordination,
    RuntimeSupervisor,
    StatsPublication,
    IdentityAllocation,
    Pacing,
    DiagnosticCounter,
    Diagnostic,
}

impl AuthorityId {
    const COUNT: usize = Self::Diagnostic as usize + 1;

    const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::FlowRead),
            1 => Some(Self::FlowReservation),
            2 => Some(Self::FlowClaim),
            3 => Some(Self::FlowWrite),
            4 => Some(Self::ManagerTransaction),
            5 => Some(Self::ManagerState),
            6 => Some(Self::SocketTopology),
            7 => Some(Self::SocketAssociation),
            8 => Some(Self::SocketDescriptor),
            9 => Some(Self::SocketIo),
            10 => Some(Self::ControlObservation),
            11 => Some(Self::ProtocolTransmit),
            12 => Some(Self::ProtocolReceive),
            13 => Some(Self::ResetBudget),
            14 => Some(Self::SessionControl),
            15 => Some(Self::Activity),
            16 => Some(Self::Maintenance),
            17 => Some(Self::WakeGeneration),
            18 => Some(Self::ReceiverClaim),
            19 => Some(Self::WaitCoordination),
            20 => Some(Self::RuntimeSupervisor),
            21 => Some(Self::StatsPublication),
            22 => Some(Self::IdentityAllocation),
            23 => Some(Self::Pacing),
            24 => Some(Self::DiagnosticCounter),
            25 => Some(Self::Diagnostic),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityDomain {
    Flow,
    Manager,
    Socket,
    Protocol,
    Runtime,
    Stats,
    Diagnostic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnershipModel {
    Lane,
    FifoReservation,
    Mutex,
    Counter,
    SingleWriter,
    UniqueClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstancePolicy {
    SingletonNonReentrant,
    AtMostOne,
    StrictAscending(InstanceKeyKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstanceKeyKind {
    Flow,
    SocketSlot,
    Direction,
    Worker,
    Session,
    ReservationTicket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityRecord {
    pub(crate) id: AuthorityId,
    pub(crate) domain: AuthorityDomain,
    pub(crate) blocking: bool,
    pub(crate) hot_path: bool,
    pub(crate) directional: bool,
    pub(crate) owner: OwnershipModel,
    pub(crate) instance_rule: &'static str,
    pub(crate) invalidation: &'static str,
    pub(crate) publication: &'static str,
}

impl AuthorityRecord {
    pub(crate) const fn instance_policy(self) -> InstancePolicy {
        match self.id {
            AuthorityId::FlowRead | AuthorityId::FlowWrite => {
                InstancePolicy::StrictAscending(InstanceKeyKind::Flow)
            }
            AuthorityId::FlowReservation | AuthorityId::ManagerTransaction => {
                InstancePolicy::StrictAscending(InstanceKeyKind::ReservationTicket)
            }
            AuthorityId::ManagerState
            | AuthorityId::SocketTopology
            | AuthorityId::SocketAssociation
            | AuthorityId::SocketDescriptor
            | AuthorityId::SocketIo
            | AuthorityId::ReceiverClaim => {
                InstancePolicy::StrictAscending(InstanceKeyKind::SocketSlot)
            }
            AuthorityId::ControlObservation
            | AuthorityId::Activity
            | AuthorityId::WakeGeneration => {
                InstancePolicy::StrictAscending(InstanceKeyKind::Direction)
            }
            AuthorityId::ProtocolTransmit
            | AuthorityId::ProtocolReceive
            | AuthorityId::SessionControl => {
                InstancePolicy::StrictAscending(InstanceKeyKind::Session)
            }
            AuthorityId::StatsPublication => {
                InstancePolicy::StrictAscending(InstanceKeyKind::Worker)
            }
            AuthorityId::ResetBudget => InstancePolicy::AtMostOne,
            AuthorityId::FlowClaim
            | AuthorityId::Maintenance
            | AuthorityId::WaitCoordination
            | AuthorityId::RuntimeSupervisor
            | AuthorityId::IdentityAllocation
            | AuthorityId::Pacing
            | AuthorityId::DiagnosticCounter
            | AuthorityId::Diagnostic => InstancePolicy::SingletonNonReentrant,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum InvariantId {
    SendCompletion,
    GroupPublication,
    ReceiverTransfer,
    ControlObservation,
    StaleAssociationRetry,
    HandshakeCompletion,
    RecoveryPayload,
    StatsFinality,
    ShutdownPublication,
    ThreadOutcomePublication,
    FlowReaderDrain,
    SocketIoDrain,
    FifoReservation,
    DescriptorCacheOwnership,
    DescriptorRevocation,
    ReresolvePublication,
    MaintenancePublication,
    PacingPublication,
    FlowClaimOwnership,
    AuditSlotPublication,
    SingleConsumerTransfer,
    AssociationStateCohesion,
    FlowTopologyTypestate,
    SocketRetirementTypestate,
    WorkerStateTransaction,
    DiagnosticCapture,
}

impl InvariantId {
    const COUNT: usize = Self::DiagnosticCapture as usize + 1;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TypeIdentity {
    SendCompletionCore,
    GroupPublicationCore,
    GroupPublicationTransaction,
    ReceiverTransferCore,
    ObservationLifecycleCore,
    ObservedStaleRetry,
    HandshakeCommitCore,
    RecoverySendCore,
    StatsFinalityCore,
    ShutdownPublicationCore,
    ThreadOutcomeCore,
    FlowTopologyCoordinator,
    FlowRuntimeState,
    GlobalSyncPacer,
    ManagedSocket,
    ManagedSocketInner,
    DescriptorCacheCore,
    ReresolvePublicationCore,
    WorkerDescriptorCache,
    FifoReservationCore,
    RuntimeSupervisor,
    ReceiveSession,
    DescriptorOwner,
    ManagedReceiver,
    ManagerMetadata,
    FlowSnapshot,
    PreparedReresolveGroup,
    FlowVisibilityLease,
    DeferredPeerControl,
    OwnedPayload,
    StatsPublicationQueue,
    ShutdownCause,
    FlowClaimOwnershipCore,
    AuditSlotPublicationCore,
    SingleConsumerBootstrap,
    AssociationAuthorityState,
    StatsSealingTransaction,
    FlowTopologyTransaction,
    SocketRetirementTransaction,
    WorkerStateTransaction,
    DiagnosticCaptureTransaction,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum FieldIdentity {
    SendStates,
    SendAllocation,
    SendRetirement,
    DeferredControl,
    Receiver,
    ReceiverGeneration,
    ReceiverOwner,
    ObservationState,
    ObservationBinding,
    RetryPayload,
    RetryIdentity,
    HandshakePayload,
    HandshakePhase,
    RecoveryPayload,
    RecoveryPhase,
    ShutdownState,
    ThreadOutcome,
    GateState,
    GateLanes,
    ReservationTickets,
    DescriptorGeneration,
    DescriptorAcknowledgements,
    DescriptorOwner,
    CachedDescriptor,
    DescriptorCacheRegistration,
    DescriptorCacheEpoch,
    ReresolveManagerBundle,
    ReresolveFlowVisibility,
    FlowClaimState,
    AuditSlotState,
    AuditSlotPayload,
    SingleConsumerValue,
    AssociationPair,
    WorkerStateBundle,
    DiagnosticManagerSnapshot,
    DiagnosticFlowLease,
    DiagnosticFlowSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum FunctionIdentity {
    SendReserve,
    SendArm,
    SendObserveControl,
    SendCompleteSuccess,
    SendCompleteFailure,
    SendRequestRetirement,
    SendCompleteRetirement,
    GroupNew,
    GroupSocketTransitionsApplied,
    GroupManagerStatePrepared,
    GroupSessionCommitted,
    GroupPublishCommitted,
    GroupRollback,
    GroupPoison,
    ReceiverClaim,
    ReceiverPublishReplacement,
    ReceiverTransferToOwner,
    ReceiverOwnerExit,
    ObservationBegin,
    ObservationFinishReceive,
    ObservationBlocksExact,
    ObservationClear,
    StaleRetryNew,
    StaleRetryAuthorizeTransition,
    StaleRetryReconciled,
    StaleRetryAuthorize,
    StaleRetryComplete,
    HandshakeNew,
    HandshakeManagerPublished,
    HandshakeCommitSession,
    HandshakeBeginSend,
    HandshakeCompleteSuccess,
    HandshakeCompleteFailure,
    HandshakeRollback,
    RecoveryNew,
    RecoveryLeaseDue,
    RecoveryPrepareSequence,
    RecoveryCompleteSend,
    RecoveryObserveRecognition,
    StatsNew,
    StatsClaim,
    StatsBeginSealing,
    StatsQueuePublication,
    StatsFinishSealing,
    StatsAcceptNext,
    StatsAcknowledge,
    StatsAbandon,
    ShutdownPublishFatal,
    WorkerTerminationBegin,
    WorkerTerminationComplete,
    FlowCloseAndDrain,
    FlowReaderRelease,
    SocketCloseAndDrain,
    SocketIoRelease,
    ReservationAllocate,
    ReservationCancel,
    ReservationRelease,
    ReservationDrop,
    DescriptorCacheRegister,
    DescriptorCacheAcknowledge,
    DescriptorCacheUnregister,
    ReresolveNew,
    ReresolvePublishManager,
    ReresolvePublishFlow,
    DescriptorRequestRevocation,
    DescriptorAcknowledgeRevocation,
    SupervisorEnforceDeadline,
    ReplayAdmit,
    ReplayReset,
    MaintenancePublish,
    MaintenanceRead,
    IdentityAllocate,
    IdentityRead,
    PacingPublish,
    PacingRead,
    DiagnosticIncrement,
    DiagnosticRead,
    DescriptorCacheClone,
    DescriptorCacheUpgrade,
    RetireDescriptorAfterRevocation,
    FlowClaimReserve,
    FlowClaimCommit,
    FlowClaimTake,
    FlowClaimRelease,
    AuditSlotRegister,
    AuditSlotBegin,
    AuditSlotSeal,
    AuditSlotAbandon,
    SingleConsumerTransfer,
    AssociationPublish,
    WorkerStateRun,
    DiagnosticCaptureRun,
    FlowTopologyApplySockets,
    FlowTopologyPrepareManager,
    FlowTopologyCommitSession,
    FlowTopologyPublish,
    SocketRetireDescriptor,
    SocketBindReplacement,
    SocketPublishRetirement,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ResourceIdentity {
    OwnedField {
        owner: TypeIdentity,
        field: FieldIdentity,
        source_field: &'static str,
        resource_type: TypeIdentity,
    },
    ExclusiveLease {
        lease: TypeIdentity,
        resource_type: TypeIdentity,
    },
    AtomicProtocol(AtomicProtocolId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleOwnershipRecord {
    pub(crate) invariant: InvariantId,
    pub(crate) loom_class: LoomEvidenceClass,
    pub(crate) owner: TypeIdentity,
    pub(crate) resources: &'static [ResourceIdentity],
    pub(crate) acquisition_methods: &'static [FunctionIdentity],
    pub(crate) mutation_methods: &'static [FunctionIdentity],
    pub(crate) terminal_methods: &'static [FunctionIdentity],
    pub(crate) runtime_entry_points: &'static [FunctionIdentity],
    pub(crate) loom_entry_points: &'static [FunctionIdentity],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoomEvidenceClass {
    ProductionCore,
    PrimitiveOnly,
    NegativeControl,
    ExplanatoryModel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiagnosticClass {
    AuthorityEdge,
    ResourceOwnership,
    BadTerminalState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BadStateId {
    StrandedDeferredControl,
    MixedReresolvePublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NegativeControlExpectation {
    pub(crate) invariant: InvariantId,
    pub(crate) diagnostic_class: DiagnosticClass,
    pub(crate) source: FunctionIdentity,
    pub(crate) offending_edge: Option<BlockingEdge>,
    pub(crate) resource: Option<ResourceIdentity>,
    pub(crate) bad_terminal_state: Option<BadStateId>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockingEdge {
    pub(crate) from: AuthorityId,
    pub(crate) to: AuthorityId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoholdRule {
    pub(crate) held: AuthorityId,
    pub(crate) acquired: AuthorityId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum WaitId {
    FlowReadersDrain,
    SocketIoDrain,
    SocketTopologyPublication,
    FifoReservation,
    SupervisorTerminal,
    StatsFinalMarkers,
    DescriptorRevocation,
}

impl WaitId {
    const COUNT: usize = Self::DescriptorRevocation as usize + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitRecord {
    pub(crate) id: WaitId,
    pub(crate) retained: Option<AuthorityId>,
    pub(crate) bounded: bool,
    pub(crate) shutdown_wake: bool,
    pub(crate) waker: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitProtocolRecord {
    pub(crate) wait: WaitId,
    pub(crate) owner: TypeIdentity,
    pub(crate) predicate_read: FunctionIdentity,
    pub(crate) waiter_registration: FunctionIdentity,
    pub(crate) post_registration_recheck: FunctionIdentity,
    pub(crate) notification: FunctionIdentity,
    pub(crate) cancellation: FunctionIdentity,
    pub(crate) teardown: FunctionIdentity,
    pub(crate) loom_invariant: InvariantId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PublicationId {
    FlowGateSnapshot,
    SocketGateAssociation,
    ReceiverGeneration,
    DescriptorGeneration,
    TransmitSequence,
    ActivityLane,
    IdleTimeoutTransition,
    ControlObservationLane,
    WakeGeneration,
    ShutdownState,
    StatsProducerLifecycle,
    ReservationOwnership,
    ThreadOutcome,
    StatsNotification,
    MaintenanceDeadline,
    ListenerReplacement,
}

impl PublicationId {
    const COUNT: usize = Self::ListenerReplacement as usize + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationRecord {
    pub(crate) id: PublicationId,
    pub(crate) linearization: &'static str,
    pub(crate) ordering: &'static str,
    pub(crate) overflow: &'static str,
    pub(crate) aba_prevention: &'static str,
    pub(crate) shutdown_interaction: &'static str,
    pub(crate) rollback_advances_epoch: bool,
    pub(crate) stale_rejected: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum AtomicProtocolId {
    FlowGateSnapshot,
    ReservationOwnership,
    FlowClaimOwnership,
    ManagerPublication,
    SocketGateAssociation,
    DescriptorCacheOwnership,
    DescriptorGeneration,
    ReceiverGeneration,
    TransmitCompletion,
    ReceiveReplay,
    ControlObservation,
    ActivityPublication,
    MaintenanceDeadline,
    MaintenanceRepairOwnership,
    WakeCoalescing,
    ShutdownPublication,
    ThreadOutcome,
    AuditSlotPublication,
    StatsFinality,
    IdentityGeneration,
    PacingDeadline,
    DiagnosticCounter,
}

impl AtomicProtocolId {
    const COUNT: usize = Self::DiagnosticCounter as usize + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicRole {
    DiagnosticOnly,
    MonotonicCounter,
    Publication,
    LifecycleState,
    GenerationOrVersion,
    OwnershipClaim,
    WakeCoalescing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryOrdering {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AtomicTransition {
    pub(crate) from: &'static str,
    pub(crate) to: &'static str,
    pub(crate) linearization: FunctionIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AtomicProtocolRecord {
    pub(crate) id: AtomicProtocolId,
    pub(crate) owner: TypeIdentity,
    pub(crate) allowed_authorities: &'static [AuthorityId],
    pub(crate) role: AtomicRole,
    pub(crate) state_encoding: &'static str,
    pub(crate) allowed_writers: &'static [FunctionIdentity],
    pub(crate) allowed_readers: &'static [FunctionIdentity],
    pub(crate) allowed_transitions: &'static [AtomicTransition],
    pub(crate) allowed_orderings: &'static [MemoryOrdering],
    pub(crate) linearization_points: &'static [FunctionIdentity],
    pub(crate) loom_invariants: &'static [InvariantId],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EffectSet(u32);

impl EffectSet {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const MAY_LOCK: Self = Self(1 << 0);
    pub(crate) const MAY_BLOCK: Self = Self(1 << 1);
    pub(crate) const MAY_WAIT: Self = Self(1 << 2);
    pub(crate) const MAY_ALLOCATE: Self = Self(1 << 3);
    pub(crate) const MAY_FORMAT: Self = Self(1 << 4);
    pub(crate) const MAY_LOG: Self = Self(1 << 5);
    pub(crate) const MAY_INVOKE_CALLBACK: Self = Self(1 << 6);
    pub(crate) const MAY_PERFORM_IO: Self = Self(1 << 7);
    pub(crate) const MAY_DROP_UNBOUNDED: Self = Self(1 << 8);
    pub(crate) const MAY_PANIC: Self = Self(1 << 9);
    pub(crate) const MAY_RUN_UNBOUNDED: Self = Self(1 << 10);
    pub(crate) const MAY_CLONE_REFCOUNT: Self = Self(1 << 11);
    pub(crate) const MAY_FINALIZE_REFCOUNT: Self = Self(1 << 12);
    pub(crate) const ALL: Self = Self::MAY_LOCK
        .union(Self::MAY_BLOCK)
        .union(Self::MAY_WAIT)
        .union(Self::MAY_ALLOCATE)
        .union(Self::MAY_FORMAT)
        .union(Self::MAY_LOG)
        .union(Self::MAY_INVOKE_CALLBACK)
        .union(Self::MAY_PERFORM_IO)
        .union(Self::MAY_DROP_UNBOUNDED)
        .union(Self::MAY_PANIC)
        .union(Self::MAY_RUN_UNBOUNDED)
        .union(Self::MAY_CLONE_REFCOUNT)
        .union(Self::MAY_FINALIZE_REFCOUNT);

    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum OperationId {
    SocketCreate,
    SocketBind,
    SocketConnect,
    SocketDisconnect,
    SocketPeerInspection,
    SocketLocalInspection,
    SocketConfigure,
    SocketCaptureEnable,
    Poll,
    SocketSend,
    SocketReceive,
    WakeSocketSend,
    WakeSocketReceive,
    TopologyDrain,
    ThreadSleep,
    CondvarWait,
    SupervisorHintSend,
    ChannelSend,
    ChannelReceive,
    Allocator,
    Formatting,
    Logging,
    JsonSerialization,
    FatalPublication,
    RefcountFinalize,
    SocketDescriptorClose,
    ThreadJoin,
    StatsFlush,
    FixedQueue,
    ProcessImmediateExit,
    PipelineBarrier,
    RefcountClone,
    RefcountUpgrade,
}

impl OperationId {
    const COUNT: usize = Self::RefcountUpgrade as usize + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OperationRecord {
    pub(crate) id: OperationId,
    pub(crate) blocking: bool,
    pub(crate) effects: EffectSet,
    pub(crate) permitted_while_held: &'static [AuthorityId],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockingClass {
    Nonblocking,
    BoundedByDeadline,
    KernelBoundedFallback,
    PotentiallyUninterruptible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WatchdogOwner {
    RuntimeSupervisor,
    ParentProcess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptMechanism {
    NoneRequired,
    WakeDescriptor,
    ConditionVariableNotification,
    ProcessTermination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalResponse {
    ReturnTypedTimeout,
    FatalGateClosed,
    FatalProcessExit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceSource {
    ProductionCoreLoom(InvariantId),
    DeterministicRegression(InvariantId),
    PlatformReality,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockingContract {
    pub(crate) operation: OperationId,
    pub(crate) blocking_class: BlockingClass,
    pub(crate) deadline_owner: TypeIdentity,
    pub(crate) watchdog_owner: WatchdogOwner,
    pub(crate) interrupt_mechanism: InterruptMechanism,
    pub(crate) terminal_response: TerminalResponse,
    pub(crate) evidence_source: EvidenceSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OperationRequirement {
    pub(crate) operation: OperationId,
    pub(crate) authority: AuthorityId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SharedRmwId {
    FlowLanePublication,
    SocketLanePublication,
    ControlObservationLanePublication,
    ManagedSocketLifetimePin,
    DescriptorReferenceCount,
    TransmitSequenceAllocation,
    StatsQueuePublication,
    GlobalCadencePacing,
}

impl SharedRmwId {
    const COUNT: usize = Self::GlobalCadencePacing as usize + 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedRmwDisposition {
    Approved,
    Forbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SharedRmwRecord {
    pub(crate) id: SharedRmwId,
    pub(crate) protocol: AtomicProtocolId,
    pub(crate) authority: AuthorityId,
    pub(crate) directional: bool,
    pub(crate) stable_path: bool,
    pub(crate) disposition: SharedRmwDisposition,
    pub(crate) contract: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DropClass {
    Trivial,
    BoundedInfallible,
    AuthorityCleanup,
    PotentiallyAllocating,
    PotentiallyBlocking,
    UnboundedContainer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReferenceCountOwnershipRecord {
    pub(crate) resource: ResourceIdentity,
    pub(crate) wrapper: TypeIdentity,
    pub(crate) clone_methods: &'static [FunctionIdentity],
    pub(crate) upgrade_methods: &'static [FunctionIdentity],
    pub(crate) permitted_authorities: &'static [AuthorityId],
    pub(crate) retirement_owner: TypeIdentity,
    pub(crate) final_drop_owner: TypeIdentity,
    pub(crate) final_drop_method: FunctionIdentity,
    pub(crate) final_drop_class: DropClass,
}
pub(crate) trait AuthoritySpec: tags::Sealed + 'static {
    const RECORD: AuthorityRecord;
    const ATOMIC_PROTOCOL: AtomicProtocolId;
}

const fn atomic_protocol_for_authority(id: AuthorityId) -> AtomicProtocolId {
    match id {
        AuthorityId::FlowRead | AuthorityId::FlowWrite => AtomicProtocolId::FlowGateSnapshot,
        AuthorityId::FlowReservation | AuthorityId::ManagerTransaction => {
            AtomicProtocolId::ReservationOwnership
        }
        AuthorityId::FlowClaim => AtomicProtocolId::FlowClaimOwnership,
        AuthorityId::ManagerState => AtomicProtocolId::ManagerPublication,
        AuthorityId::SocketTopology | AuthorityId::SocketAssociation | AuthorityId::SocketIo => {
            AtomicProtocolId::SocketGateAssociation
        }
        AuthorityId::SocketDescriptor => AtomicProtocolId::DescriptorGeneration,
        AuthorityId::ControlObservation => AtomicProtocolId::ControlObservation,
        AuthorityId::ProtocolTransmit => AtomicProtocolId::TransmitCompletion,
        AuthorityId::ProtocolReceive | AuthorityId::SessionControl => {
            AtomicProtocolId::ReceiveReplay
        }
        AuthorityId::ResetBudget | AuthorityId::IdentityAllocation => {
            AtomicProtocolId::IdentityGeneration
        }
        AuthorityId::Activity => AtomicProtocolId::ActivityPublication,
        AuthorityId::Maintenance => AtomicProtocolId::MaintenanceDeadline,
        AuthorityId::WakeGeneration | AuthorityId::WaitCoordination => {
            AtomicProtocolId::WakeCoalescing
        }
        AuthorityId::ReceiverClaim => AtomicProtocolId::ReceiverGeneration,
        AuthorityId::RuntimeSupervisor => AtomicProtocolId::ShutdownPublication,
        AuthorityId::StatsPublication => AtomicProtocolId::StatsFinality,
        AuthorityId::Pacing => AtomicProtocolId::PacingDeadline,
        AuthorityId::DiagnosticCounter | AuthorityId::Diagnostic => {
            AtomicProtocolId::DiagnosticCounter
        }
    }
}

pub(crate) mod tags;

fn publish_poison(id: AuthorityId) {
    crate::runtime_support::publish_process_fatal(format_args!(
        "synchronization authority {id:?} is poisoned"
    ));
}

#[cfg(any(test, feature = "authority-audit"))]
pub(crate) fn audit_allocator_boundary() {
    audit::allocator_boundary();
}

#[cfg(any(test, feature = "authority-audit"))]
pub(crate) fn record_pipeline_stage(direction: bool, stage: usize) {
    audit::record_pipeline_stage(direction, stage);
}

#[cfg(any(test, feature = "authority-audit"))]
pub(crate) fn record_payload_copy() {
    audit::record_payload_copy();
}

#[cfg(all(test, not(miri)))]
mod tests;
